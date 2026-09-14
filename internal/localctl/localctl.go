// Package localctl exposes the small, local-only control API used by the
// command line client.  The API is carried over a per-profile Unix socket or
// Windows named pipe; it never opens a TCP listener.
package localctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/config"
)

const (
	defaultClientTimeout = 5 * time.Second
	requestBodyLimit     = 1 << 20
	responseBodyLimit    = 1 << 20
)

var (
	// ErrAlreadyRunning means another process owns the profile's control lock.
	ErrAlreadyRunning = errors.New("local control server already running")
	// ErrNotRunning is a marker for a local control endpoint that is absent.
	// Callers should use IsNotRunning because the underlying operating-system
	// error is wrapped by net/http and differs between Unix sockets and Windows
	// named pipes.
	ErrNotRunning = errors.New("local control server is not running")
	// ErrSocketPathTooLong means the Unix socket name cannot be represented by
	// the operating system. It is never returned on Windows, which uses a
	// named pipe instead.
	ErrSocketPathTooLong = errors.New("local control socket path too long")
)

// IsNotRunning reports whether err proves that a profile's local control
// endpoint is absent or refused a connection.  It deliberately excludes
// permission, malformed-endpoint, and timeout errors: those may indicate a
// live process or a broken installation and should remain visible to callers.
func IsNotRunning(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrNotRunning) || isNotRunningError(err)
}

var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// Server is a local control HTTP server. A Server owns the profile lock for
// its entire lifetime and releases it only after its serving goroutine exits.
type Server struct {
	httpServer *http.Server
	listener   net.Listener
	lock       profileLock
	cleanup    func() error

	done      chan struct{}
	closeErr  error
	closeMu   sync.Mutex
	closeOnce sync.Once
}

type profileLock interface {
	Close() error
}

// Listen starts the local control server for name in dir. status is called for
// GET /status and its return value is JSON encoded. stop is scheduled in a
// goroutine after a successful POST /stop response has been written; it may be
// nil when the caller has no stop action.
func Listen(ctx context.Context, dir, name string, status func() any, stop func()) (*Server, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	if status == nil {
		return nil, errors.New("nil status callback")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := validateDirectory(dir)
	if err != nil {
		return nil, err
	}
	if err := validateName(name); err != nil {
		return nil, err
	}
	if err := checkEndpointLength(dir, name); err != nil {
		return nil, err
	}

	lock, err := acquireProfileLock(dir, name)
	if err != nil {
		return nil, err
	}

	listener, cleanup, err := listenEndpoint(dir, name)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = listener.Close()
		_ = cleanup()
		_ = lock.Close()
		return nil, err
	}

	server := &Server{
		listener: listener,
		lock:     lock,
		cleanup:  cleanup,
		done:     make(chan struct{}),
	}
	server.httpServer = &http.Server{
		Handler:           newHandler(status, stop),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	go func() {
		_ = server.httpServer.Serve(server.listener)
		close(server.done)
		// A listener can terminate because of an unexpected permanent
		// accept error. Release the profile lock in that case as well; the
		// normal Close path is protected by closeOnce and remains idempotent.
		_ = server.Close()
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-server.done:
		}
	}()
	return server, nil
}

// Close stops the server and waits until its serving goroutine has exited.
// It is safe to call concurrently and repeatedly.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		// Closing the listener wakes Serve even when no request is active. The
		// HTTP server close also terminates any accepted connections.
		err := s.httpServer.Close()
		<-s.done
		if cleanupErr := s.cleanup(); err == nil {
			err = cleanupErr
		}
		if lockErr := s.lock.Close(); err == nil {
			err = lockErr
		}
		s.closeMu.Lock()
		s.closeErr = err
		s.closeMu.Unlock()
	})
	s.closeMu.Lock()
	err := s.closeErr
	s.closeMu.Unlock()
	return err
}

func newHandler(status func() any, stop func()) http.Handler {
	var stopOnce sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := consumeRequestBody(w, r); err != nil {
			return
		}
		switch r.URL.Path {
		case "/status":
			if r.Method != http.MethodGet {
				methodNotAllowed(w, http.MethodGet)
				return
			}
			value, err := invokeStatus(status)
			if err != nil {
				http.Error(w, "status unavailable", http.StatusInternalServerError)
				return
			}
			body, err := json.Marshal(value)
			if err != nil {
				http.Error(w, "status unavailable", http.StatusInternalServerError)
				return
			}
			if len(body) > responseBodyLimit {
				http.Error(w, "status response too large", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		case "/stop":
			if r.Method != http.MethodPost {
				methodNotAllowed(w, http.MethodPost)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"stopping":true}`))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			stopOnce.Do(func() {
				if stop != nil {
					go stop()
				}
			})
		default:
			http.NotFound(w, r)
		}
	})
}

func consumeRequestBody(w http.ResponseWriter, r *http.Request) error {
	if r.ContentLength > requestBodyLimit {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return errors.New("request body too large")
	}
	if r.Body == nil {
		return nil
	}
	limited := http.MaxBytesReader(w, r.Body, requestBodyLimit)
	_, err := io.Copy(io.Discard, limited)
	closeErr := r.Body.Close()
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

func methodNotAllowed(w http.ResponseWriter, method string) {
	w.Header().Set("Allow", method)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func invokeStatus(status func() any) (value any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("status callback panic: %v", recovered)
		}
	}()
	return status(), nil
}

// Status retrieves GET /status from the local server and decodes its JSON
// response into out. A context without a deadline receives a five second
// default timeout.
func Status(ctx context.Context, dir, name string, out any) error {
	if out == nil {
		return errors.New("nil status output")
	}
	return doRequest(ctx, dir, name, http.MethodGet, "/status", out)
}

// Stop asks the local server to stop. The server sends the HTTP response
// before scheduling the caller's stop callback.
func Stop(ctx context.Context, dir, name string) error {
	return doRequest(ctx, dir, name, http.MethodPost, "/stop", nil)
}

func doRequest(ctx context.Context, dir, name, method, path string, out any) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	dir, err := validateDirectory(dir)
	if err != nil {
		return err
	}
	if err := validateName(name); err != nil {
		return err
	}
	if err := checkEndpointLength(dir, name); err != nil {
		return err
	}
	if err := validateClientEndpoint(dir, name); err != nil {
		return err
	}

	requestCtx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, method, "http://local.control"+path, nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			ForceAttemptHTTP2:   false,
			DisableCompression:  true,
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     30 * time.Second,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialEndpoint(ctx, dir, name)
			},
		},
	}
	transport := client.Transport.(*http.Transport)
	defer transport.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
		if len(body) != 0 {
			return fmt.Errorf("local control: %s: %s", response.Status, bytes.TrimSpace(body))
		}
		return fmt.Errorf("local control: %s", response.Status)
	}
	if out == nil {
		_, err = readBounded(response.Body, responseBodyLimit)
		return err
	}
	body, err := readBounded(response.Body, responseBodyLimit)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode local status: %w", err)
	}
	return nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("local control response too large")
	}
	return body, nil
}

func withDefaultTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, defaultClientTimeout)
}

func validateName(name string) error {
	if !validName.MatchString(name) {
		return errors.New("invalid local control name")
	}
	return nil
}

func validateDirectory(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("empty local control directory")
	}
	clean := filepath.Clean(dir)
	if err := rejectSymlinkComponents(clean); err != nil {
		return "", err
	}
	// The state directory is initialized by config.Store. Lstat before
	// calling Init is intentional: local control must never create a missing
	// directory, and Init's platform policy must inspect an existing one
	// without rewriting its mode or ACL.
	st, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("local control directory: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return "", errors.New("local control directory must be a real directory")
	}
	store := config.Store{Dir: clean}
	if err := store.Init(); err != nil {
		return "", fmt.Errorf("local control directory: %w", err)
	}
	return clean, nil
}

func rejectSymlinkComponents(path string) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, volume)
	current := volume
	if strings.HasPrefix(rest, string(filepath.Separator)) {
		current += string(filepath.Separator)
		rest = strings.TrimPrefix(rest, string(filepath.Separator))
	}
	for _, component := range strings.Split(rest, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		st, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect local control path: %w", err)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("local control path must not contain a symlink")
		}
	}
	return nil
}
