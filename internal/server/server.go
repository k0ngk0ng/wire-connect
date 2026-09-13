// Package server combines authenticated rendezvous, DERP-over-WebSocket and STUN.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/control"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/time/rate"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type Config struct {
	Domain              string
	Listen              string
	STUNListen          string
	StateDir            string
	CertFile            string
	KeyFile             string
	EnrollmentToken     string
	EnrollmentOutput    io.Writer
	MaxRelayConnections int
	RelayBytesPerSecond uint64
	Log                 *slog.Logger
}

type Server struct {
	Control           *control.Server
	relay             *derpserver.Server
	admission         *http.Server
	admissionListener net.Listener
	mux               *http.ServeMux
	cfg               Config
	once              sync.Once
}

func New(cfg Config) (*Server, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.MaxRelayConnections == 0 {
		cfg.MaxRelayConnections = 256
	}
	if cfg.MaxRelayConnections < 1 || cfg.MaxRelayConnections > 100000 {
		return nil, errors.New("invalid relay connection limit")
	}
	if cfg.RelayBytesPerSecond == 0 {
		cfg.RelayBytesPerSecond = 10 << 20
	}
	store := config.Store{Dir: cfg.StateDir}
	if err := store.Init(); err != nil {
		return nil, err
	}
	var relayState struct {
		Private key.NodePrivate `json:"private"`
	}
	if err := store.Read("relay", &relayState); errors.Is(err, os.ErrNotExist) {
		relayState.Private = key.NewNode()
		if err := store.Write("relay", relayState); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if relayState.Private.IsZero() {
		return nil, errors.New("invalid persisted relay key")
	}
	controlDir := filepath.Join(cfg.StateDir, "control")
	generated := false
	if _, err := os.Stat(filepath.Join(controlDir, "state.json")); errors.Is(err, os.ErrNotExist) && cfg.EnrollmentToken == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		cfg.EnrollmentToken = base64.RawURLEncoding.EncodeToString(b)
		generated = true
	}
	ctl, err := control.New(control.Config{StateDir: controlDir, EnrollmentToken: cfg.EnrollmentToken, Log: cfg.Log})
	if err != nil {
		return nil, err
	}
	s := &Server{Control: ctl, cfg: cfg, mux: http.NewServeMux()}
	s.relay = derpserver.New(relayState.Private, func(format string, args ...any) { cfg.Log.Debug(fmt.Sprintf(format, args...)) })
	s.relay.UpdateRateLimits(derpserver.RateConfig{PerClientRateLimitBytesPerSec: cfg.RelayBytesPerSecond, PerClientRateBurstBytes: cfg.RelayBytesPerSecond})
	s.admissionListener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.Close()
		return nil, err
	}
	s.admission = &http.Server{Handler: http.HandlerFunc(s.admit), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	s.relay.SetVerifyClientURL("http://" + s.admissionListener.Addr().String() + "/verify")
	s.relay.SetVerifyClientURLFailOpen(false)
	go func() {
		if err := s.admission.Serve(s.admissionListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			cfg.Log.Error("relay admission stopped", "error", err)
		}
	}()
	base := derpserver.AddWebSocketSupport(s.relay, derpserver.Handler(s.relay))
	slots := make(chan struct{}, cfg.MaxRelayConnections)
	s.mux.Handle("/derp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clients use a real WebSocket transport on every platform, allowing
		// standard HTTPS proxies and reverse proxies to carry the DERP stream.
		if r.Method != "GET" || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "DERP WebSocket required", http.StatusUpgradeRequired)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "relay connection limit", http.StatusServiceUnavailable)
			return
		}
		// Renew the admission decision periodically. Clients reconnect with
		// bounded backoff; authorization leases are never valid indefinitely.
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		base.ServeHTTP(w, r.WithContext(ctx))
	}))
	s.mux.Handle("/", ctl.Handler())
	if generated && cfg.EnrollmentOutput != nil {
		fmt.Fprintf(cfg.EnrollmentOutput, "Enrollment token (save now; shown once): %s\n", cfg.EnrollmentToken)
	}
	s.cfg.EnrollmentToken = ""
	cfg.EnrollmentToken = ""
	return s, nil
}

func (s *Server) admit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.Path != "/verify" {
		http.NotFound(w, r)
		return
	}
	var req tailcfg.DERPAdmitClientRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid admission request", 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{Allow: s.Control.AllowedRelayKey(req.NodePublic.UntypedHexString())})
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) Close() error {
	var errs []error
	s.once.Do(func() {
		if s.relay != nil {
			errs = append(errs, s.relay.Close())
		}
		if s.admission != nil {
			errs = append(errs, s.admission.Close())
		} else if s.admissionListener != nil {
			errs = append(errs, s.admissionListener.Close())
		}
		if s.Control != nil {
			errs = append(errs, s.Control.Close())
		}
	})
	return errors.Join(errs...)
}

func Serve(ctx context.Context, cfg Config) error {
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if cfg.STUNListen == "" {
		cfg.STUNListen = ":3478"
	}
	if cfg.Domain == "" && (cfg.CertFile == "" || cfg.KeyFile == "") {
		return errors.New("serve requires --domain for automatic TLS, or both --cert and --key")
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return errors.New("--cert and --key must be supplied together")
	}
	s, err := New(cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	udp, err := net.ListenPacket("udp", cfg.STUNListen)
	if err != nil {
		return fmt.Errorf("listen STUN: %w", err)
	}
	defer udp.Close()
	stunCtx, stopSTUN := context.WithCancel(ctx)
	defer stopSTUN()
	go func() { <-stunCtx.Done(); udp.Close() }()
	go ServeSTUN(stunCtx, udp)
	httpServer := &http.Server{Addr: cfg.Listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if cfg.CertFile == "" {
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(cfg.Domain), Cache: autocert.DirCache(filepath.Join(cfg.StateDir, "certificates"))}
		httpServer.TLSConfig = m.TLSConfig()
		httpServer.TLSConfig.MinVersion = tls.VersionTLS12
	}
	listen, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen HTTPS: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- httpServer.ServeTLS(listen, cfg.CertFile, cfg.KeyFile) }()
	s.cfg.Log.Info("server listening", "https", listen.Addr().String(), "stun", udp.LocalAddr().String())
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = httpServer.Shutdown(shutdownCtx)
	if err != nil {
		httpServer.Close()
	}
	return err
}

// ServeSTUN answers only valid binding requests. A global token bucket bounds
// the service even under spoofed source-address floods; responses are small.
func ServeSTUN(ctx context.Context, pc net.PacketConn) error {
	lim := rate.NewLimiter(1000, 2000)
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !lim.Allow() {
			continue
		}
		tx, err := stun.ParseBindingRequest(buf[:n])
		if err != nil {
			continue
		}
		udp, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		response := stun.Response(tx, udp.AddrPort())
		if _, err := pc.WriteTo(response, addr); err != nil && ctx.Err() != nil {
			return nil
		}
	}
}
