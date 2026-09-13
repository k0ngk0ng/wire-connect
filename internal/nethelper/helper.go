// Package nethelper limits elevated work to a single point-to-point IPv4 TUN.
// Authentication uses OS-protected local IPC; credentials and WireGuard run in
// the calling user's process. The helper never reads user configuration files.
package nethelper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

const protocolVersion = 1
const maxPacket = 65535
const packetFrame byte = 1
const eventFrame byte = 2

var ErrUnavailable = errors.New("network helper is unavailable; run wirectl connect setup once")
var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,14}$`)
var sharedRange = netip.MustParsePrefix("100.64.0.0/10")

type Config struct {
	Name  string `json:"name"`
	Local string `json:"local"`
	Peer  string `json:"peer"`
	MTU   int    `json:"mtu"`
}
type OpenFunc func(context.Context, Config) (tun.Device, func() error, error)
type request struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	Config    Config `json:"config"`
}
type response struct {
	Version int    `json:"version"`
	Error   string `json:"error,omitempty"`
	Name    string `json:"name,omitempty"`
	MTU     int    `json:"mtu,omitempty"`
}

func ValidateConfig(c Config) error {
	if !validName.MatchString(c.Name) {
		return errors.New("invalid tunnel interface name")
	}
	if c.MTU < 576 || c.MTU > maxPacket {
		return errors.New("invalid tunnel MTU")
	}
	local, err := netip.ParseAddr(c.Local)
	if err != nil || !allowedAddress(local) {
		return errors.New("local address must be private IPv4 or CGNAT unicast")
	}
	peer, err := netip.ParseAddr(c.Peer)
	if err != nil || !allowedAddress(peer) || peer == local {
		return errors.New("peer address must be a different private IPv4 or CGNAT unicast")
	}
	return nil
}
func allowedAddress(a netip.Addr) bool {
	return a.Is4() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast() && (a.IsPrivate() || sharedRange.Contains(a))
}

func Check(ctx context.Context) error {
	c, err := dial(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer c.Close()
	_, err = exchange(ctx, c, request{Version: protocolVersion, Operation: "check"})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

func Open(ctx context.Context, cfg Config) (tun.Device, func() error, error) {
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, nil, err
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	r, err := exchange(ctx, conn, request{Version: protocolVersion, Operation: "open", Config: cfg})
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if !validName.MatchString(r.Name) || r.MTU != cfg.MTU {
		conn.Close()
		return nil, nil, errors.New("invalid network helper response")
	}
	dev := newProxy(conn, r.Name, r.MTU)
	stop := context.AfterFunc(ctx, func() { _ = dev.Close() })
	return dev, func() error { stop(); return dev.Close() }, nil
}

func exchange(ctx context.Context, c net.Conn, r request) (response, error) {
	timeout := 15 * time.Second
	if r.Operation == "open" {
		timeout = 45 * time.Second
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if err := writeJSON(c, r); err != nil {
		return response{}, err
	}
	var result response
	if err := readJSON(c, &result); err != nil {
		return result, err
	}
	_ = c.SetDeadline(time.Time{})
	if result.Version != protocolVersion {
		return result, errors.New("network helper protocol mismatch; run wirectl connect setup to update it")
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, nil
}

// Serve accepts only the identity authorized by the administrator during setup.
// A bounded number of authenticated sessions may each own one independent TUN.
func Serve(ctx context.Context, identity string, open OpenFunc) error {
	if open == nil {
		return errors.New("missing TUN opener")
	}
	listener, cleanup, err := listen(identity)
	if err != nil {
		return err
	}
	defer cleanup()
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	slots := make(chan struct{}, 8)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if err := authenticate(conn, identity); err != nil {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			defer conn.Close()
			_ = serveConn(ctx, conn, open)
		}()
	}
}

func serveConn(ctx context.Context, conn net.Conn, open OpenFunc) error {
	return serveConnWithLock(ctx, conn, open, networkLock)
}

func serveConnWithLock(ctx context.Context, conn net.Conn, open OpenFunc, lock func(context.Context) (func(), error)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var req request
	if err := readJSON(conn, &req); err != nil {
		return err
	}
	reply := func(err error) error {
		r := response{Version: protocolVersion}
		if err != nil {
			r.Error = err.Error()
		}
		return writeJSON(conn, r)
	}
	if req.Version != protocolVersion {
		return reply(errors.New("network helper protocol mismatch"))
	}
	if req.Operation == "check" {
		return reply(nil)
	}
	if req.Operation != "open" {
		return reply(errors.New("unknown network helper operation"))
	}
	if err := ValidateConfig(req.Config); err != nil {
		return reply(err)
	}
	// The initial deadline only bounds reading the request. A first Windows
	// adapter may also install a driver, configure routes and wait for DAD.
	// Bound that work separately, including time waiting for another helper.
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	setupCtx, setupCancel := context.WithTimeout(ctx, 30*time.Second)
	defer setupCancel()
	// Serialize route check and setup across per-user helper services.
	unlock, err := lock(setupCtx)
	if err != nil {
		return reply(err)
	}
	dev, cleanup, err := open(setupCtx, req.Config)
	setupCancel()
	unlock()
	if err != nil {
		return reply(err)
	}
	if dev == nil || cleanup == nil {
		if dev != nil {
			dev.Close()
		}
		return reply(errors.New("invalid TUN opener result"))
	}
	originalCleanup := cleanup
	var cleanupOnce sync.Once
	var cleanupErr error
	cleanup = func() error {
		cleanupOnce.Do(func() {
			// Teardown mutates the same routes as setup. Keep it serialized even
			// after the client or service has canceled its session context.
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			unlock, err := lock(cleanupCtx)
			if err != nil {
				_ = dev.Close()
				cleanupErr = fmt.Errorf("lock network teardown: %w", err)
				return
			}
			defer unlock()
			cleanupErr = originalCleanup()
		})
		return cleanupErr
	}
	defer func() { _ = cleanup() }()
	name, err := dev.Name()
	if err != nil {
		return reply(err)
	}
	if err := writeJSON(conn, response{Version: protocolVersion, Name: name, MTU: req.Config.MTU}); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	return bridge(ctx, conn, dev, req.Config, cleanup)
}

func bridge(ctx context.Context, conn net.Conn, dev tun.Device, cfg Config, cleanup func() error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	local := netip.MustParseAddr(cfg.Local).As4()
	peer := netip.MustParseAddr(cfg.Peer).As4()
	var writeMu sync.Mutex
	send := func(payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return writeFrame(conn, payload)
	}
	result := make(chan error, 3)
	var wg sync.WaitGroup
	launch := func(fn func() error) { wg.Add(1); go func() { defer wg.Done(); result <- fn() }() }
	launch(func() error {
		count := dev.BatchSize()
		if count < 1 || count > 128 {
			return errors.New("invalid TUN batch size")
		}
		bufs := make([][]byte, count)
		sizes := make([]int, count)
		for i := range bufs {
			bufs[i] = make([]byte, maxPacket+64)
		}
		for {
			n, err := dev.Read(bufs, sizes, 64)
			if err != nil {
				return err
			}
			for i := 0; i < n; i++ {
				p := bufs[i][64 : 64+sizes[i]]
				if !validPacket(p, local, peer) {
					continue
				}
				frame := make([]byte, 1+len(p))
				frame[0] = packetFrame
				copy(frame[1:], p)
				if err := send(frame); err != nil {
					return err
				}
			}
		}
	})
	launch(func() error {
		for {
			frame, err := readFrame(conn, maxPacket+1)
			if err != nil {
				return err
			}
			if len(frame) < 2 || frame[0] != packetFrame || !validPacket(frame[1:], peer, local) {
				return errors.New("invalid packet sent to network helper")
			}
			buf := make([]byte, 64+len(frame)-1)
			copy(buf[64:], frame[1:])
			if _, err := dev.Write([][]byte{buf}, 64); err != nil {
				return err
			}
		}
	})
	launch(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case e, ok := <-dev.Events():
				if !ok {
					return io.EOF
				}
				frame := make([]byte, 5)
				frame[0] = eventFrame
				binary.BigEndian.PutUint32(frame[1:], uint32(e))
				if err := send(frame); err != nil {
					return err
				}
			}
		}
	})
	var err error
	select {
	case err = <-result:
	case <-ctx.Done():
		err = ctx.Err()
	}
	cancel()
	_ = conn.Close()
	_ = cleanup()
	wg.Wait()
	return err
}

func validPacket(p []byte, source, destination [4]byte) bool {
	if len(p) < 20 || p[0]>>4 != 4 || int(p[0]&15)*4 < 20 || int(p[0]&15)*4 > len(p) || int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
		return false
	}
	return [4]byte(p[12:16]) == source && [4]byte(p[16:20]) == destination
}
func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFrame(w, b)
}
func readJSON(r io.Reader, v any) error {
	b, err := readFrame(r, 4096)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func writeFrame(w io.Writer, p []byte) error {
	if len(p) == 0 || len(p) > maxPacket+1 {
		return errors.New("invalid IPC frame length")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	if _, err := io.Copy(w, bytes.NewReader(h[:])); err != nil {
		return err
	}
	_, err := io.Copy(w, bytes.NewReader(p))
	return err
}
func readFrame(r io.Reader, limit int) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > uint32(limit) {
		return nil, errors.New("invalid IPC frame length")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

// proxy implements tun.Device without privileged syscalls in the user process.
type proxy struct {
	conn    net.Conn
	name    string
	mtu     int
	packets chan []byte
	events  chan tun.Event
	done    chan struct{}
	once    sync.Once
	writeMu sync.Mutex
}

func newProxy(c net.Conn, name string, mtu int) *proxy {
	p := &proxy{conn: c, name: name, mtu: mtu, packets: make(chan []byte, 64), events: make(chan tun.Event, 16), done: make(chan struct{})}
	p.events <- tun.EventUp
	go p.receive()
	return p
}
func (p *proxy) receive() {
	defer close(p.events)
	defer close(p.packets)
	defer p.Close()
	for {
		frame, err := readFrame(p.conn, maxPacket+1)
		if err != nil {
			return
		}
		switch frame[0] {
		case packetFrame:
			if len(frame) < 21 {
				return
			}
			select {
			case p.packets <- frame[1:]:
			case <-p.done:
				return
			}
		case eventFrame:
			if len(frame) != 5 {
				return
			}
			e := tun.Event(binary.BigEndian.Uint32(frame[1:]))
			select {
			case p.events <- e:
			case <-p.done:
				return
			}
		default:
			return
		}
	}
}
func (p *proxy) File() *os.File           { return nil }
func (p *proxy) Name() (string, error)    { return p.name, nil }
func (p *proxy) MTU() (int, error)        { return p.mtu, nil }
func (p *proxy) Events() <-chan tun.Event { return p.events }
func (p *proxy) BatchSize() int           { return 1 }
func (p *proxy) Close() error {
	var err error
	p.once.Do(func() { close(p.done); err = p.conn.Close() })
	return err
}
func (p *proxy) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || offset < 0 || offset > len(bufs[0]) {
		return 0, errors.New("invalid TUN read buffers")
	}
	b, ok := <-p.packets
	if !ok {
		return 0, os.ErrClosed
	}
	if len(b) > len(bufs[0])-offset {
		return 0, io.ErrShortBuffer
	}
	sizes[0] = copy(bufs[0][offset:], b)
	return 1, nil
}
func (p *proxy) Write(bufs [][]byte, offset int) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	for i, b := range bufs {
		if offset < 0 || offset > len(b) || len(b)-offset > maxPacket {
			return i, errors.New("invalid TUN write buffer")
		}
		frame := make([]byte, 1+len(b)-offset)
		frame[0] = packetFrame
		copy(frame[1:], b[offset:])
		_ = p.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := writeFrame(p.conn, frame); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}
