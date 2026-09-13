package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/server"
)

// The ordinary test terminates TLS at a reverse proxy and forwards plain HTTP
// to the backend. The opt-in case exercises an operator-provided real proxy,
// using a disposable server state during deployment qualification. Neither
// case creates an operating-system TUN or changes local routes.
func TestWireGuardThroughTLSReverseProxy(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		token := strings.Repeat("proxy-test-enrollment-", 3)
		backend, err := server.New(server.Config{StateDir: filepath.Join(t.TempDir(), "server"), EnrollmentToken: token})
		if err != nil {
			t.Fatal(err)
		}
		defer backend.Close()
		plain := httptest.NewServer(backend.Handler())
		defer plain.Close()
		upstream, _ := url.Parse(plain.URL)
		proxy := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(upstream))
		defer proxy.Close()
		fingerprint := sha256.Sum256(proxy.Certificate().Raw)
		checkProxyWireGuard(t, proxy.URL, token, hex.EncodeToString(fingerprint[:]))
	})
	t.Run("deployed", func(t *testing.T) {
		origin := os.Getenv("WIRE_CONNECT_PROXY_TEST_SERVER")
		if origin == "" {
			t.Skip("set WIRE_CONNECT_PROXY_TEST_SERVER and WIRE_CONNECT_PROXY_TEST_TOKEN_FILE for an authorized disposable server")
		}
		if !strings.HasPrefix(origin, "https://") {
			t.Fatal("deployed proxy qualification requires HTTPS")
		}
		secret, err := os.ReadFile(os.Getenv("WIRE_CONNECT_PROXY_TEST_TOKEN_FILE"))
		if err != nil {
			t.Fatal(err)
		}
		defer clear(secret)
		checkProxyWireGuard(t, origin, strings.TrimSpace(string(secret)), "")
	})
}

func checkProxyWireGuard(t *testing.T, origin, token, pin string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	newPeer := func(name string) *Client {
		c, err := New(origin, config.Credential{CertificateSHA256: pin})
		if err != nil {
			t.Fatal(err)
		}
		cred, err := c.Login(ctx, token, "proxy-qualification-"+name)
		if err != nil {
			t.Fatal(err)
		}
		c.Credential = cred
		return c
	}
	a, b := newPeer("a"), newPeer("b")
	type result struct {
		profile config.Profile
		err     error
	}
	codes := make(chan string, 1)
	host := make(chan result, 1)
	check := func(context.Context, ...netip.Addr) error { return nil }
	go func() {
		p, err := a.Pair(ctx, PairOptions{Host: true, AddressCheck: check, OnCode: func(s string) { codes <- s }})
		host <- result{p, err}
	}()
	var code string
	select {
	case code = <-codes:
	case r := <-host:
		t.Fatalf("host pairing failed: %v", r.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	bp, err := b.Pair(ctx, PairOptions{Code: code, AddressCheck: check})
	if err != nil {
		t.Fatal(err)
	}
	var ap config.Profile
	select {
	case r := <-host:
		if r.err != nil {
			t.Fatal(r.err)
		}
		ap = r.profile
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	ta, tb := newMemoryTUN(), newMemoryTUN()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	runs := make(chan error, 2)
	go func() { runs <- a.Run(ctx, ap, RunOptions{TUN: ta, RelayOnly: true, Log: quiet}) }()
	go func() { runs <- b.Run(ctx, bp, RunOptions{TUN: tb, RelayOnly: true, Log: quiet}) }()
	defer func() {
		cancel()
		for range 2 {
			select {
			case <-runs:
			case <-time.After(5 * time.Second):
				t.Error("proxy client did not stop")
			}
		}
	}()
	transfer := func(from, to *memoryTUN, source, destination string) {
		t.Helper()
		packet := udpPacket(netip.MustParseAddr(source), netip.MustParseAddr(destination), []byte("verified WireGuard payload through TLS termination"))
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case from.read <- packet:
			default:
			}
			select {
			case got := <-to.written:
				if bytes.Equal(got, packet) {
					return
				}
			case <-ticker.C:
			case <-ctx.Done():
				t.Fatal("encrypted proxy transfer timed out:", ctx.Err())
			}
		}
	}
	transfer(ta, tb, ap.LocalIP, ap.PeerIP)
	transfer(tb, ta, bp.LocalIP, bp.PeerIP)
}
