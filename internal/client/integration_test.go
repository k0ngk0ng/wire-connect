package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/server"
	"golang.zx2c4.com/wireguard/tun"
)

// memoryTUN crosses the exact wireguard-go TUN boundary without modifying the
// machine running this test. Packets still pass through the real WireGuard
// encryption, DERP protocol, HTTPS/WebSocket server and peer decryption.
type memoryTUN struct {
	read    chan []byte
	written chan []byte
	done    chan struct{}
	events  chan tun.Event
	once    sync.Once
}

func newMemoryTUN() *memoryTUN {
	t := &memoryTUN{read: make(chan []byte, 32), written: make(chan []byte, 32), done: make(chan struct{}), events: make(chan tun.Event, 1)}
	t.events <- tun.EventUp
	return t
}
func (t *memoryTUN) File() *os.File           { return nil }
func (t *memoryTUN) MTU() (int, error)        { return 1420, nil }
func (t *memoryTUN) Name() (string, error)    { return "test-tun", nil }
func (t *memoryTUN) Events() <-chan tun.Event { return t.events }
func (t *memoryTUN) BatchSize() int           { return 1 }
func (t *memoryTUN) Close() error             { t.once.Do(func() { close(t.done); close(t.events) }); return nil }
func (t *memoryTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.done:
		return 0, os.ErrClosed
	case p := <-t.read:
		if len(bufs) == 0 || len(sizes) == 0 || len(bufs[0])-offset < len(p) {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	}
}
func (t *memoryTUN) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if offset > len(b) {
			return i, io.ErrShortBuffer
		}
		p := bytes.Clone(b[offset:])
		select {
		case t.written <- p:
		case <-t.done:
			return i, os.ErrClosed
		}
	}
	return len(bufs), nil
}

func TestPairedWireGuardOverHTTPSRelayAndDirect(t *testing.T) {
	for _, relayOnly := range []bool{true, false} {
		t.Run(fmt.Sprintf("relay_only_%t", relayOnly), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
			serverState := filepath.Join(t.TempDir(), "server")
			srv, err := server.New(server.Config{StateDir: serverState, EnrollmentToken: strings.Repeat("enrollment", 5), Log: quiet})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			var activeServer atomic.Pointer[server.Server]
			activeServer.Store(srv)
			httpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { activeServer.Load().Handler().ServeHTTP(w, r) }))
			defer httpServer.Close()
			pin := sha256.Sum256(httpServer.Certificate().Raw)
			newClient := func(name string) *Client {
				c, err := New(httpServer.URL, config.Credential{CertificateSHA256: hex.EncodeToString(pin[:])})
				if err != nil {
					t.Fatal(err)
				}
				cred, err := c.Login(ctx, strings.Repeat("enrollment", 5), name)
				if err != nil {
					t.Fatal(err)
				}
				c.Credential = cred
				return c
			}
			a, b := newClient("a"), newClient("b")
			code := make(chan string, 1)
			type pairResult struct {
				profile config.Profile
				err     error
			}
			pa := make(chan pairResult, 1)
			check := func(context.Context, ...netip.Addr) error { return nil }
			go func() {
				p, err := a.Pair(ctx, PairOptions{Host: true, OnCode: func(c string) { code <- c }, AddressCheck: check})
				pa <- pairResult{p, err}
			}()
			var shortCode string
			select {
			case shortCode = <-code:
			case result := <-pa:
				t.Fatalf("host failed before creating code: %v", result.err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			bp, err := b.Pair(ctx, PairOptions{Code: shortCode, AddressCheck: check})
			if err != nil {
				t.Fatal("guest pair:", err)
			}
			ar := <-pa
			if ar.err != nil {
				t.Fatal("host pair:", ar.err)
			}
			ap := ar.profile
			if ap.PairID != bp.PairID || !bytes.Equal(ap.Secret, bp.Secret) || ap.LocalIP != bp.PeerIP || ap.PeerIP != bp.LocalIP {
				t.Fatal("pair identities or addresses differ")
			}
			store := config.Store{Dir: filepath.Join(t.TempDir(), "client")}
			if err := store.Write("profile-default", ap); err != nil {
				t.Fatal(err)
			}
			var restored config.Profile
			if err := store.Read("profile-default", &restored); err != nil {
				t.Fatal(err)
			}
			ap = restored
			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			go server.ServeSTUN(ctx, udp)
			stunURL := "stun:" + udp.LocalAddr().String()
			ta, tb := newMemoryTUN(), newMemoryTUN()
			runCtx, stop := context.WithCancel(ctx)
			defer stop()
			runs := make(chan error, 2)
			direct := make(chan struct{}, 2)
			status := func(s Status) {
				if s.Mode == "direct" {
					select {
					case direct <- struct{}{}:
					default:
					}
				}
			}
			go func() {
				runs <- a.Run(runCtx, ap, RunOptions{TUN: ta, RelayOnly: relayOnly, STUNURL: stunURL, Log: quiet, OnStatus: status})
			}()
			go func() {
				runs <- b.Run(runCtx, bp, RunOptions{TUN: tb, RelayOnly: relayOnly, STUNURL: stunURL, Log: quiet, OnStatus: status})
			}()
			transfer := func(from, to *memoryTUN, src, dst string, payload string) {
				t.Helper()
				packet := udpPacket(netip.MustParseAddr(src), netip.MustParseAddr(dst), []byte(payload))
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
					case err := <-runs:
						t.Fatalf("tunnel stopped: %v", err)
					case <-ticker.C:
					case <-ctx.Done():
						t.Fatal("packet transfer timed out:", ctx.Err())
					}
				}
			}
			transfer(ta, tb, ap.LocalIP, ap.PeerIP, "application payload A to B")
			transfer(tb, ta, bp.LocalIP, bp.PeerIP, "application payload B to A")
			if !relayOnly {
				select {
				case <-direct:
				case err := <-runs:
					t.Fatal(err)
				case <-ctx.Done():
					t.Fatal("never upgraded to direct", ctx.Err())
				}
				transfer(ta, tb, ap.LocalIP, ap.PeerIP, "application payload after direct upgrade")
				if err := srv.Close(); err != nil {
					t.Fatal(err)
				}
				transfer(ta, tb, ap.LocalIP, ap.PeerIP, "direct payload while public server is offline")
			} else {
				if err := srv.Close(); err != nil {
					t.Fatal(err)
				}
				restarted, err := server.New(server.Config{StateDir: serverState, Log: quiet})
				if err != nil {
					t.Fatal("restart server:", err)
				}
				defer restarted.Close()
				activeServer.Store(restarted)
				transfer(ta, tb, ap.LocalIP, ap.PeerIP, "relay payload after server restart")
				transfer(tb, ta, bp.LocalIP, bp.PeerIP, "reverse relay payload after server restart")
			}
			stop()
			for range 2 {
				select {
				case err := <-runs:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("client did not shut down")
				}
			}
		})
	}
}

func udpPacket(src, dst netip.Addr, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	a, b := src.As4(), dst.As4()
	copy(p[12:16], a[:])
	copy(p[16:20], b[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	binary.BigEndian.PutUint16(p[20:22], 12345)
	binary.BigEndian.PutUint16(p[22:24], 54321)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}
