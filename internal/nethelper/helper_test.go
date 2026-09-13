package nethelper

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

func TestValidateConfig(t *testing.T) {
	base := Config{Name: "wc-test", Local: "100.64.0.1", Peer: "10.23.0.2", MTU: 1420}
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"RFC1918", base},
		{"CGNAT", Config{Name: "w0", Local: "100.127.255.254", Peer: "192.168.1.1", MTU: 576}},
		{"minimum MTU", Config{Name: "A_0-1", Local: "172.16.0.1", Peer: "172.31.255.254", MTU: 576}},
		{"maximum MTU", Config{Name: "123456789012345", Local: "10.0.0.1", Peer: "10.0.0.2", MTU: maxPacket}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateConfig(tc.cfg); err != nil {
				t.Fatalf("ValidateConfig(%+v) = %v", tc.cfg, err)
			}
		})
	}

	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"empty name", func(c *Config) { c.Name = "" }},
		{"name starts with punctuation", func(c *Config) { c.Name = "-wc0" }},
		{"name contains punctuation", func(c *Config) { c.Name = "wc.0" }},
		{"name too long", func(c *Config) { c.Name = "1234567890123456" }},
		{"MTU below minimum", func(c *Config) { c.MTU = 575 }},
		{"MTU above maximum", func(c *Config) { c.MTU = maxPacket + 1 }},
		{"zero MTU", func(c *Config) { c.MTU = 0 }},
		{"public local", func(c *Config) { c.Local = "8.8.8.8" }},
		{"loopback local", func(c *Config) { c.Local = "127.0.0.1" }},
		{"unspecified local", func(c *Config) { c.Local = "0.0.0.0" }},
		{"multicast local", func(c *Config) { c.Local = "224.0.0.1" }},
		{"link-local local", func(c *Config) { c.Local = "169.254.1.1" }},
		{"IPv6 local", func(c *Config) { c.Local = "fd00::1" }},
		{"public peer", func(c *Config) { c.Peer = "1.1.1.1" }},
		{"same endpoints", func(c *Config) { c.Peer = c.Local }},
		{"invalid local text", func(c *Config) { c.Local = "not-an-address" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.edit(&cfg)
			if err := ValidateConfig(cfg); err == nil {
				t.Fatalf("ValidateConfig(%+v) unexpectedly succeeded", cfg)
			}
		})
	}
}

func TestIPCFrameLengthValidation(t *testing.T) {
	if err := writeFrame(io.Discard, nil); err == nil {
		t.Fatal("writeFrame accepted an empty frame")
	}
	if err := writeFrame(io.Discard, make([]byte, maxPacket+2)); err == nil {
		t.Fatal("writeFrame accepted a frame larger than the protocol limit")
	}

	valid := bytes.Repeat([]byte{0xa5}, maxPacket+1)
	var encoded bytes.Buffer
	if err := writeFrame(&encoded, valid); err != nil {
		t.Fatalf("writeFrame at the maximum length: %v", err)
	}
	decoded, err := readFrame(&encoded, maxPacket+1)
	if err != nil {
		t.Fatalf("readFrame at the maximum length: %v", err)
	}
	if !bytes.Equal(decoded, valid) {
		t.Fatal("readFrame changed a maximum length frame")
	}

	for _, tc := range []struct {
		name string
		n    uint32
		lim  int
	}{
		{"zero", 0, maxPacket + 1},
		{"above limit", 10, 9},
		{"above protocol limit", maxPacket + 2, maxPacket + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], tc.n)
			if _, err := readFrame(bytes.NewReader(b[:]), tc.lim); err == nil {
				t.Fatalf("readFrame accepted length %d with limit %d", tc.n, tc.lim)
			}
		})
	}
	if _, err := readFrame(bytes.NewReader([]byte{0, 0, 0, 4, 1, 2}), 4); err == nil {
		t.Fatal("readFrame accepted a truncated frame")
	}
}

func TestValidPacketChecksIPv4HeaderAndEndpoints(t *testing.T) {
	src := netip.MustParseAddr("100.64.0.1").As4()
	dst := netip.MustParseAddr("100.64.0.2").As4()
	valid := testIPv4Packet(src, dst, []byte("payload"))

	tests := []struct {
		name string
		edit func([]byte) []byte
		want bool
	}{
		{"valid", func(p []byte) []byte { return p }, true},
		{"too short", func([]byte) []byte { return make([]byte, 19) }, false},
		{"wrong version", func(p []byte) []byte { p[0] = 0x65; return p }, false},
		{"short header length", func(p []byte) []byte { p[0] = 0x44; return p }, false},
		{"header longer than packet", func(p []byte) []byte { p[0] = 0x46; return p[:20] }, false},
		{"declared total length short", func(p []byte) []byte { binary.BigEndian.PutUint16(p[2:4], uint16(len(p)-1)); return p }, false},
		{"declared total length long", func(p []byte) []byte { binary.BigEndian.PutUint16(p[2:4], uint16(len(p)+1)); return p }, false},
		{"wrong source", func(p []byte) []byte { p[12] ^= 1; return p }, false},
		{"wrong destination", func(p []byte) []byte { p[16] ^= 1; return p }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validPacket(tc.edit(append([]byte(nil), valid...)), src, dst)
			if got != tc.want {
				t.Fatalf("validPacket() = %v, want %v", got, tc.want)
			}
		})
	}

	withOptions := testIPv4Packet(src, dst, []byte("payload"))
	withOptions = append(withOptions, 0, 0, 0, 0)
	withOptions[0] = 0x46
	binary.BigEndian.PutUint16(withOptions[2:4], uint16(len(withOptions)))
	if !validPacket(withOptions, src, dst) {
		t.Fatal("validPacket rejected a valid IPv4 packet with options")
	}
}

func TestExchangeRejectsProtocolMismatch(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverDone := make(chan error, 1)
	go func() {
		var req request
		if err := readJSON(server, &req); err != nil {
			serverDone <- err
			return
		}
		serverDone <- writeJSON(server, response{Version: protocolVersion + 1})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := exchange(ctx, client, request{Version: protocolVersion, Operation: "check"})
	if err == nil || !strings.Contains(err.Error(), "protocol mismatch") {
		t.Fatalf("exchange error = %v, want protocol mismatch", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("test server: %v", err)
	}
}

func TestServeConnCheckAndVersionValidation(t *testing.T) {
	valid := Config{Name: "wc-test", Local: "100.64.0.1", Peer: "10.23.0.2", MTU: 1420}
	tests := []struct {
		name      string
		request   request
		wantError string
		wantOpens int
	}{
		{name: "check", request: request{Version: protocolVersion, Operation: "check"}},
		{name: "request version mismatch", request: request{Version: protocolVersion + 1, Operation: "check"}, wantError: "protocol mismatch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			var opens atomic.Int32
			done := make(chan error, 1)
			go func() {
				done <- serveConnWithLock(context.Background(), server, func(context.Context, Config) (tun.Device, func() error, error) {
					opens.Add(1)
					return nil, nil, errors.New("open must not be called")
				}, noNetworkLock)
			}()
			if err := writeJSON(client, tc.request); err != nil {
				t.Fatalf("write request: %v", err)
			}
			var reply response
			if err := readJSON(client, &reply); err != nil {
				t.Fatalf("read response: %v", err)
			}
			if reply.Version != protocolVersion {
				t.Fatalf("response version = %d, want %d", reply.Version, protocolVersion)
			}
			if tc.wantError == "" && reply.Error != "" {
				t.Fatalf("unexpected response error: %s", reply.Error)
			}
			if tc.wantError != "" && !strings.Contains(reply.Error, tc.wantError) {
				t.Fatalf("response error = %q, want %q", reply.Error, tc.wantError)
			}
			select {
			case err := <-done:
				if tc.wantError == "" && err != nil {
					t.Fatalf("serveConn returned %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("serveConn did not finish")
			}
			if got := opens.Load(); int(got) != tc.wantOpens {
				t.Fatalf("open calls = %d, want %d", got, tc.wantOpens)
			}
		})
	}

	// A valid open request must return the helper-owned interface and MTU, then
	// leave the connection in packet bridge mode.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	dev := newTestDevice("wc-helper", valid.MTU)
	var cleanupCalls atomic.Int32
	var locks atomic.Int32
	var locked atomic.Bool
	var cleanupLocked atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- serveConnWithLock(context.Background(), server, func(_ context.Context, cfg Config) (tun.Device, func() error, error) {
			if cfg != valid {
				return nil, nil, errors.New("unexpected config")
			}
			return dev, func() error {
				cleanupCalls.Add(1)
				cleanupLocked.Store(locked.Load())
				return dev.Close()
			}, nil
		}, func(ctx context.Context) (func(), error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			locks.Add(1)
			locked.Store(true)
			return func() { locked.Store(false) }, nil
		})
	}()
	if err := writeJSON(client, request{Version: protocolVersion, Operation: "open", Config: valid}); err != nil {
		t.Fatalf("write open request: %v", err)
	}
	var reply response
	if err := readJSON(client, &reply); err != nil {
		t.Fatalf("read open response: %v", err)
	}
	if reply.Error != "" || reply.Name != dev.name || reply.MTU != valid.MTU {
		t.Fatalf("open response = %+v", reply)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("serveConn did not clean up after disconnect")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
	if locks.Load() != 2 || !cleanupLocked.Load() || locked.Load() {
		t.Fatal("setup and teardown must each hold and release the network lock")
	}
}

func TestBridgeAndProxyBidirectionalPacketFlow(t *testing.T) {
	server, client := net.Pipe()
	dev := newTestDevice("wc-helper", 1420)
	cfg := Config{Name: dev.name, Local: "100.64.0.1", Peer: "100.64.0.2", MTU: 1420}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cleanupCalls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- bridge(ctx, server, dev, cfg, func() error {
			cleanupCalls.Add(1)
			return dev.Close()
		})
	}()
	proxy := newProxy(client, "wc-helper", cfg.MTU)
	defer proxy.Close()

	select {
	case event, ok := <-proxy.Events():
		if !ok || event != tun.EventUp {
			t.Fatalf("initial proxy event = %v, open = %v", event, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for proxy event")
	}

	local, peer := netip.MustParseAddr(cfg.Local).As4(), netip.MustParseAddr(cfg.Peer).As4()
	localPacket := testIPv4Packet(local, peer, []byte("local to peer"))
	dev.read <- localPacket
	got := readProxyPacket(t, proxy)
	if !bytes.Equal(got, localPacket) {
		t.Fatalf("local packet = %x, want %x", got, localPacket)
	}

	peerPacket := testIPv4Packet(peer, local, []byte("peer to local"))
	frame := make([]byte, 64+len(peerPacket))
	copy(frame[64:], peerPacket)
	if n, err := proxy.Write([][]byte{frame}, 64); err != nil || n != 1 {
		t.Fatalf("proxy.Write() = %d, %v", n, err)
	}
	select {
	case got = <-dev.written:
		if !bytes.Equal(got, peerPacket) {
			t.Fatalf("injected packet = %x, want %x", got, peerPacket)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for peer packet injection")
	}

	// A packet read from the privileged device must be restricted to the
	// configured local-to-peer direction. It is silently discarded otherwise.
	dev.read <- testIPv4Packet(peer, local, []byte("forged local output"))
	type readResult struct {
		packet []byte
		err    error
	}
	readDone := make(chan readResult, 1)
	go func() {
		buf := make([]byte, maxPacket+64)
		sizes := make([]int, 1)
		_, err := proxy.Read([][]byte{buf}, sizes, 64)
		if err != nil {
			readDone <- readResult{err: err}
			return
		}
		readDone <- readResult{packet: append([]byte(nil), buf[64:64+sizes[0]]...)}
	}()
	select {
	case result := <-readDone:
		if result.err != nil {
			t.Fatalf("proxy.Read after filtered packet: %v", result.err)
		}
		t.Fatal("bridge forwarded a packet in the wrong direction")
	case <-time.After(50 * time.Millisecond):
	}
	validAgain := testIPv4Packet(local, peer, []byte("valid after filter"))
	dev.read <- validAgain
	select {
	case result := <-readDone:
		if result.err != nil {
			t.Fatalf("proxy.Read after valid packet: %v", result.err)
		}
		if !bytes.Equal(result.packet, validAgain) {
			t.Fatalf("packet after filter = %x, want %x", result.packet, validAgain)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out reading packet after filtered packet")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bridge did not stop after context cancellation")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestBridgeRejectsForgedPeerInjectionDirection(t *testing.T) {
	server, client := net.Pipe()
	dev := newTestDevice("wc-helper", 1420)
	cfg := Config{Name: dev.name, Local: "100.64.0.1", Peer: "100.64.0.2", MTU: 1420}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cleanupCalls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- bridge(ctx, server, dev, cfg, func() error {
			cleanupCalls.Add(1)
			return dev.Close()
		})
	}()
	proxy := newProxy(client, "wc-helper", cfg.MTU)
	defer proxy.Close()

	local, peer := netip.MustParseAddr(cfg.Local).As4(), netip.MustParseAddr(cfg.Peer).As4()
	forged := testIPv4Packet(local, peer, []byte("user forged output"))
	frame := make([]byte, 64+len(forged))
	copy(frame[64:], forged)
	if n, err := proxy.Write([][]byte{frame}, 64); err != nil || n != 1 {
		t.Fatalf("proxy.Write() = %d, %v", n, err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "invalid packet") {
			t.Fatalf("bridge error = %v, want invalid packet", err)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge accepted forged packet")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func noNetworkLock(context.Context) (func(), error) { return func() {}, nil }

type testDevice struct {
	name    string
	mtu     int
	read    chan []byte
	written chan []byte
	events  chan tun.Event
	done    chan struct{}
	once    sync.Once
	closed  atomic.Int32
}

func newTestDevice(name string, mtu int) *testDevice {
	d := &testDevice{name: name, mtu: mtu, read: make(chan []byte, 8), written: make(chan []byte, 8), events: make(chan tun.Event, 4), done: make(chan struct{})}
	d.events <- tun.EventUp
	return d
}

func (d *testDevice) File() *os.File           { return nil }
func (d *testDevice) MTU() (int, error)        { return d.mtu, nil }
func (d *testDevice) Name() (string, error)    { return d.name, nil }
func (d *testDevice) Events() <-chan tun.Event { return d.events }
func (d *testDevice) BatchSize() int           { return 1 }
func (d *testDevice) Close() error {
	d.once.Do(func() {
		d.closed.Add(1)
		close(d.done)
		close(d.events)
	})
	return nil
}
func (d *testDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset > len(bufs[0]) {
		return 0, errors.New("invalid test TUN read buffers")
	}
	select {
	case <-d.done:
		return 0, os.ErrClosed
	case packet := <-d.read:
		if len(packet) > len(bufs[0])-offset {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	}
}
func (d *testDevice) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		if offset < 0 || offset > len(buf) {
			return i, errors.New("invalid test TUN write offset")
		}
		packet := append([]byte(nil), buf[offset:]...)
		select {
		case <-d.done:
			return i, os.ErrClosed
		case d.written <- packet:
		}
	}
	return len(bufs), nil
}

func testIPv4Packet(src, dst [4]byte, payload []byte) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	copy(p[20:], payload)
	return p
}

func readProxyPacket(t *testing.T, p *proxy) []byte {
	t.Helper()
	type result struct {
		packet []byte
		err    error
	}
	got := make(chan result, 1)
	go func() {
		buf := make([]byte, maxPacket+64)
		sizes := make([]int, 1)
		n, err := p.Read([][]byte{buf}, sizes, 64)
		if err != nil {
			got <- result{err: err}
			return
		}
		if n != 1 {
			got <- result{err: errors.New("proxy returned an invalid packet count")}
			return
		}
		got <- result{packet: append([]byte(nil), buf[64:64+sizes[0]]...)}
	}()
	select {
	case r := <-got:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.packet
	case <-time.After(time.Second):
		t.Fatal("timed out reading packet from proxy")
		return nil
	}
}
