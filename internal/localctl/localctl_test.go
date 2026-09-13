package localctl

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/config"
)

func TestListenStatusStop(t *testing.T) {
	dir := testDirectory(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopCalled := make(chan struct{})
	var stopCount atomic.Int32
	server, err := Listen(ctx, dir, "default", func() any {
		return map[string]any{"state": "connected", "count": 2}
	}, func() {
		if stopCount.Add(1) == 1 {
			close(stopCalled)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	var status map[string]any
	if err := Status(context.Background(), dir, "default", &status); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status["state"] != "connected" || status["count"] != float64(2) {
		t.Fatalf("unexpected status: %#v", status)
	}
	if err := Stop(context.Background(), dir, "default"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case <-stopCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("stop callback was not called")
	}
	if got := stopCount.Load(); got != 1 {
		t.Fatalf("stop callback count = %d, want 1", got)
	}
}

func TestStopSchedulesCallbackAfterResponse(t *testing.T) {
	dir := testDirectory(t)
	started := make(chan struct{})
	release := make(chan struct{})
	server, err := Listen(context.Background(), dir, "async", func() any { return nil }, func() {
		close(started)
		<-release
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(release)
		_ = server.Close()
	}()

	begin := time.Now()
	if err := Stop(context.Background(), dir, "async"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("Stop waited for asynchronous callback: %s", elapsed)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("stop callback was not scheduled")
	}
}

func TestSecondInstanceRejectedAndCloseReleasesProfile(t *testing.T) {
	dir := testDirectory(t)
	ctx := context.Background()
	first, err := Listen(ctx, dir, "profile", func() any { return "ok" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(ctx, dir, "profile", func() any { return "other" }, nil); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Listen error = %v, want ErrAlreadyRunning", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	second, err := Listen(ctx, dir, "profile", func() any { return "ok" }, nil)
	if err != nil {
		t.Fatalf("Listen after Close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestCrossProcessInstanceRejected(t *testing.T) {
	dir := testDirectory(t)
	server, err := Listen(context.Background(), dir, "process", func() any { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalctlLockHelper$", "-test.v")
	command.Env = append(os.Environ(),
		"LOCALCTL_LOCK_HELPER=1",
		"LOCALCTL_LOCK_DIR="+dir,
		"LOCALCTL_LOCK_NAME=process",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("cross-process lock helper: %v\n%s", err, output)
	}
}

func TestLocalctlLockHelper(t *testing.T) {
	if os.Getenv("LOCALCTL_LOCK_HELPER") != "1" {
		return
	}
	_, err := Listen(context.Background(), os.Getenv("LOCALCTL_LOCK_DIR"), os.Getenv("LOCALCTL_LOCK_NAME"), func() any { return nil }, nil)
	if errors.Is(err, ErrAlreadyRunning) {
		return
	}
	if err == nil {
		t.Fatal("helper acquired a second profile lock")
	}
	t.Fatalf("helper got unexpected error: %v", err)
}

func TestCloseIsIdempotentAndContextCancels(t *testing.T) {
	dir := testDirectory(t)
	ctx, cancel := context.WithCancel(context.Background())
	server, err := Listen(ctx, dir, "cancel", func() any { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := server.Close(); err != nil {
		t.Fatalf("Close after context cancellation: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	second, err := Listen(context.Background(), dir, "cancel", func() any { return nil }, nil)
	if err != nil {
		t.Fatalf("Listen after cancellation: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close after cancellation: %v", err)
	}
}

func TestListenRejectsCanceledContext(t *testing.T) {
	dir := testDirectory(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Listen(ctx, dir, "canceled", func() any { return nil }, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Listen error = %v, want context.Canceled", err)
	}
}

func TestMethodAndBodyLimits(t *testing.T) {
	dir := testDirectory(t)
	server, err := Listen(context.Background(), dir, "http", func() any { return map[string]string{"ok": "yes"} }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	response := rawRequest(t, dir, "http", http.MethodPost, "/status", nil)
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /status status = %d, want %d", response.StatusCode, http.StatusMethodNotAllowed)
	}
	if got := response.Header.Get("Allow"); got != http.MethodGet {
		t.Fatalf("POST /status Allow = %q", got)
	}
	response.Body.Close()

	response = rawRequest(t, dir, "http", http.MethodGet, "/stop", nil)
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /stop status = %d, want %d", response.StatusCode, http.StatusMethodNotAllowed)
	}
	response.Body.Close()

	response = rawRequest(t, dir, "http", http.MethodGet, "/status", bytes.NewReader(make([]byte, requestBodyLimit+1)))
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d, want %d", response.StatusCode, http.StatusRequestEntityTooLarge)
	}
	response.Body.Close()
}

func TestValidation(t *testing.T) {
	dir := testDirectory(t)
	for _, name := range []string{"", "../escape", "a/b", "-leading", "space name"} {
		if _, err := Listen(context.Background(), dir, name, func() any { return nil }, nil); err == nil {
			t.Errorf("Listen name %q succeeded", name)
		}
	}
	if _, err := Listen(context.Background(), filepath.Join(dir, "missing"), "profile", func() any { return nil }, nil); err == nil {
		t.Error("Listen with missing directory succeeded")
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(context.Background(), file, "profile", func() any { return nil }, nil); err == nil {
		t.Error("Listen with file directory succeeded")
	}
}

func rawRequest(t *testing.T, dir, name, method, path string, body io.Reader) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, "http://local.control"+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.ContentLength = int64(requestBodyLimit + 1)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialEndpoint(ctx, dir, name)
		},
	}}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func testDirectory(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	// Keep Unix socket test paths below macOS's sockaddr_un limit even when
	// this repository is checked out at a long absolute path.
	base := filepath.Join(root, ".cache", "lc")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	rootDir, err := os.MkdirTemp(base, "p")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(rootDir, "state")
	if err := (config.Store{Dir: dir}).Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rootDir) })
	return dir
}
