package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/control"
	"github.com/k0ngk0ng/wire-connect/internal/transport"
	"tailscale.com/types/key"
)

func TestHTTPListenValidation(t *testing.T) {
	valid := []string{
		"127.0.0.1:8080",
		"127.255.255.254:0",
		"[::1]:8080",
	}
	for _, listen := range valid {
		t.Run("accept/"+listen, func(t *testing.T) {
			cfg, err := normalizeConfig(Config{HTTP: true, Listen: listen})
			if err != nil {
				t.Fatalf("normalizeConfig(%q): %v", listen, err)
			}
			if cfg.Listen != listen {
				t.Fatalf("normalized listen = %q, want %q", cfg.Listen, listen)
			}
		})
	}

	invalid := []string{
		"localhost:8080",
		"127.0.0.1",
		":8080",
		"0.0.0.0:8080",
		"[::]:8080",
		"192.168.1.1:8080",
		"[::1%lo]:8080",
		"::1:8080",
		"[::ffff:127.0.0.1]:8080",
		"127.0.0.1:http",
	}
	for _, listen := range invalid {
		t.Run("reject/"+strings.NewReplacer(":", "_", "%", "_").Replace(listen), func(t *testing.T) {
			if _, err := normalizeConfig(Config{HTTP: true, Listen: listen}); err == nil {
				t.Fatalf("normalizeConfig(%q) accepted an invalid HTTP listen address", listen)
			}
		})
	}
}

func TestHTTPValidationPrecedesStateInitialization(t *testing.T) {
	root := t.TempDir()
	for _, cfg := range []Config{
		{HTTP: true, Listen: "localhost:8080"},
		{HTTP: true, Listen: ":8080"},
		{HTTP: true, Listen: "127.0.0.1:8080", Domain: "example.test"},
	} {
		stateDir := filepath.Join(root, "state-"+strings.ReplaceAll(cfg.Listen, ":", "-"))
		cfg.StateDir = stateDir
		if _, err := New(cfg); err == nil {
			t.Fatalf("New(%+v) accepted invalid HTTP configuration", cfg)
		}
		if _, err := os.Stat(stateDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid HTTP configuration touched state directory %q: %v", stateDir, err)
		}
	}
}

func TestHTTPServeHealthAndDERP(t *testing.T) {
	httpAddr := reserveTCPAddress(t)
	stunAddr := reserveUDPAddress(t)
	stateDir := filepath.Join(t.TempDir(), "server")
	const enrollmentToken = "http-test-enrollment-token-http-test-enrollment-token"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, Config{
			HTTP:            true,
			Listen:          httpAddr,
			STUNListen:      stunAddr,
			StateDir:        stateDir,
			EnrollmentToken: enrollmentToken,
			Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop during cleanup")
		}
	})

	baseURL := "http://" + httpAddr
	waitForHealth(t, baseURL)

	var login control.LoginResponse
	doJSON(t, http.MethodPost, baseURL+"/v1/login", "", control.LoginRequest{Token: enrollmentToken, Name: "http-test"}, &login)
	if login.Token == "" {
		t.Fatal("login returned an empty device token")
	}

	private := key.NewNode()
	doJSON(t, http.MethodPost, baseURL+"/v1/relay/register", login.Token, control.RelayRegisterRequest{Key: private.Public().UntypedHexString()}, nil)

	bind, err := transport.New(ctx, transport.RelayConfig{
		URL:     baseURL,
		Private: private,
		Peer:    key.NewNode().Public(),
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal("create relay bind:", err)
	}
	defer bind.Shutdown()
	relayCtx, stopRelayWait := context.WithTimeout(ctx, 5*time.Second)
	defer stopRelayWait()
	if err := bind.WaitRelay(relayCtx); err != nil {
		t.Fatal("wait for HTTP DERP connection:", err)
	}
	if got := bind.Stats().Mode; got != "relay" {
		t.Fatalf("relay mode = %q, want relay", got)
	}
}

func reserveTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func reserveUDPAddress(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func waitForHealth(t *testing.T, baseURL string) {
	t.Helper()
	client := &http.Client{Timeout: 250 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = errors.New(resp.Status)
		} else {
			lastErr = err
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("HTTP health check did not become ready: %v", lastErr)
}

func doJSON(t *testing.T, method, url, token string, requestBody, responseBody any) {
	t.Helper()
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("%s %s: status %s body %q", method, url, resp.Status, response)
	}
	if responseBody != nil {
		if err := json.Unmarshal(response, responseBody); err != nil {
			t.Fatalf("decode %s response: %v", url, err)
		}
	}
}
