// Package transport contains the packet transport used by the WireGuard
// device.  It deliberately keeps the transport independent from the TUN and
// operating-system setup: the latter is owned by internal/platform.
package transport

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	wgconn "golang.zx2c4.com/wireguard/conn"
	"tailscale.com/derp"
	"tailscale.com/types/key"
)

const (
	// maxPacketSize is the largest packet accepted by either path.  It is
	// deliberately the same order of magnitude as DERP's hard limit while
	// leaving room for future WireGuard packet types.
	maxPacketSize = (1 << 16) - 1
	queueDepth    = 128

	initialReconnectDelay = 250 * time.Millisecond
	maxReconnectDelay     = 30 * time.Second
	relayDialTimeout      = 15 * time.Second
	relayWriteTimeout     = 5 * time.Second
)

var (
	// ErrNoTransport means that neither a direct ICE path nor a live relay is
	// currently available.  Callers can retry after WaitRelay or a new direct
	// path notification.
	ErrNoTransport = errors.New("wire-connect: no transport path available")
	// ErrRelayDisabled is returned by WaitRelay when no relay URL was
	// configured.
	ErrRelayDisabled = errors.New("wire-connect: relay is disabled")
	// ErrTransportClosed is returned by operations after Shutdown.
	ErrTransportClosed = errors.New("wire-connect: transport is shut down")
)

// RelayConfig configures a Bind's DERP fallback path.
//
// URL may be a ws:// or wss:// URL.  http:// and https:// are accepted as a
// convenience and are converted to the corresponding WebSocket scheme.  The
// /derp path is added automatically.  HTTPClient is passed to the WebSocket
// dialer unchanged, so proxy and certificate-pinning policies configured by a
// caller apply equally on all supported operating systems.
type RelayConfig struct {
	URL        string
	Private    key.NodePrivate
	Peer       key.NodePublic
	HTTPClient *http.Client
	Log        *slog.Logger
}

// Stats is a snapshot of Bind's packet and path state.  Sent and Received are
// payload byte counters, rather than frame or packet counters.
type Stats struct {
	Mode           string
	Sent           uint64
	Received       uint64
	RelayConnected bool
}

// Bind implements wireguard-go's conn.Bind using an ICE datagram connection
// when one is available and a DERP connection as a fallback.
//
// Open and Close describe the WireGuard listener lifecycle.  They do not tear
// down the relay or direct transport, because wireguard-go may close and
// reopen a Bind while applying a new configuration.  Shutdown is the final
// lifecycle operation.
type Bind struct {
	ctx    context.Context
	cancel context.CancelFunc

	private key.NodePrivate
	peer    key.NodePublic
	url     string
	client  *http.Client
	log     *slog.Logger

	endpoint *virtualEndpoint
	inbound  chan []byte

	lifecycleMu sync.Mutex
	active      *receiveGeneration
	shutdown    bool
	stopped     atomic.Bool
	shutdownCh  chan struct{}

	pathMu sync.RWMutex
	direct *directPath
	relay  *relaySession
	wake   chan struct{}

	sendMu sync.Mutex

	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64

	workers       sync.WaitGroup
	workerMu      sync.Mutex
	workersClosed bool
	stopOnce      sync.Once
}

var _ wgconn.Bind = (*Bind)(nil)

type receiveGeneration struct {
	done chan struct{}
	once sync.Once
}

func (g *receiveGeneration) close() {
	if g == nil {
		return
	}
	g.once.Do(func() { close(g.done) })
}

func (g *receiveGeneration) closed() bool {
	if g == nil {
		return true
	}
	select {
	case <-g.done:
		return true
	default:
		return false
	}
}

type directPath struct {
	conn net.Conn
}

type relaySession struct {
	nc     net.Conn
	client *derp.Client

	closeOnce sync.Once
}

func (s *relaySession) close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		if s.nc != nil {
			_ = s.nc.Close()
		}
	})
}

// New constructs a Bind without waiting for the relay to become reachable.
// The returned Bind starts a reconnecting relay worker when cfg.URL is set.
func New(ctx context.Context, cfg RelayConfig) (*Bind, error) {
	if ctx == nil {
		return nil, errors.New("wire-connect: nil context")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if cfg.Private.IsZero() {
		return nil, errors.New("wire-connect: relay private key is zero")
	}
	if cfg.Peer.IsZero() {
		return nil, errors.New("wire-connect: relay peer key is zero")
	}

	relayURL, err := normalizeRelayURL(cfg.URL)
	if err != nil {
		return nil, err
	}

	bindCtx, cancel := context.WithCancel(ctx)
	b := &Bind{
		ctx:        bindCtx,
		cancel:     cancel,
		private:    cfg.Private,
		peer:       cfg.Peer,
		url:        relayURL,
		client:     cfg.HTTPClient,
		log:        cfg.Log,
		endpoint:   &virtualEndpoint{addr: netip.MustParseAddrPort("127.0.0.1:1")},
		inbound:    make(chan []byte, queueDepth),
		shutdownCh: make(chan struct{}),
		wake:       make(chan struct{}),
	}

	if relayURL != "" {
		b.workers.Add(1)
		go b.relayLoop()
	}

	// A context cancellation is a final lifecycle event.  This goroutine is
	// intentionally not part of workers: Shutdown waits for network workers and
	// may itself be called from this watcher.
	go func() {
		<-bindCtx.Done()
		_ = b.Shutdown()
	}()
	return b, nil
}

// Open starts the WireGuard receive generation.  There is no kernel UDP
// socket, so the returned port is the stable synthetic endpoint port.
func (b *Bind) Open(_ uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	if b == nil {
		return nil, 0, ErrTransportClosed
	}
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()
	if b.shutdown {
		return nil, 0, ErrTransportClosed
	}
	if b.active != nil {
		return nil, 0, wgconn.ErrBindAlreadyOpen
	}
	g := &receiveGeneration{done: make(chan struct{})}
	b.active = g
	return []wgconn.ReceiveFunc{b.receive(g)}, 1, nil
}

// Close ends the current WireGuard receive generation.  It is safe to call
// repeatedly and deliberately leaves background paths alive for a later Open.
func (b *Bind) Close() error {
	if b == nil {
		return nil
	}
	b.lifecycleMu.Lock()
	g := b.active
	b.active = nil
	b.lifecycleMu.Unlock()
	if g != nil {
		g.close()
	}
	return nil
}

// Shutdown permanently closes all transport paths and workers.  It is safe to
// call more than once.
func (b *Bind) Shutdown() error {
	if b == nil {
		return nil
	}
	b.stopOnce.Do(func() {
		b.stopped.Store(true)
		b.workerMu.Lock()
		b.workersClosed = true
		b.workerMu.Unlock()
		b.lifecycleMu.Lock()
		b.shutdown = true
		g := b.active
		b.active = nil
		b.lifecycleMu.Unlock()
		if g != nil {
			g.close()
		}
		close(b.shutdownCh)
		b.cancel()

		b.pathMu.Lock()
		direct := b.direct
		b.direct = nil
		relay := b.relay
		b.relay = nil
		b.signalRelayLocked()
		b.pathMu.Unlock()
		if direct != nil && direct.conn != nil {
			_ = direct.conn.Close()
		}
		if relay != nil {
			relay.close()
		}
		b.workers.Wait()
	})
	return nil
}

// SetMark is part of wireguard-go's Bind interface.  A synthetic endpoint has
// no kernel socket mark; callers can safely treat this as a no-op.
func (b *Bind) SetMark(_ uint32) error {
	if b == nil {
		return ErrTransportClosed
	}
	b.lifecycleMu.Lock()
	closed := b.shutdown
	b.lifecycleMu.Unlock()
	if closed {
		return ErrTransportClosed
	}
	return nil
}

// ParseEndpoint returns the stable virtual endpoint used for WireGuard's
// endpoint bookkeeping.  The textual address is validated for compatibility
// with callers that persist it, but the returned address is always synthetic:
// Send routes to the paired peer key rather than a network address.
func (b *Bind) ParseEndpoint(s string) (wgconn.Endpoint, error) {
	if b == nil {
		return nil, ErrTransportClosed
	}
	if _, err := netip.ParseAddrPort(s); err != nil {
		return nil, err
	}
	return &virtualEndpoint{addr: b.endpoint.addr}, nil
}

// BatchSize intentionally remains one: ICE and DERP both preserve datagram
// boundaries, and a one-packet callback keeps the lifecycle and queue logic
// straightforward across all supported operating systems.
func (*Bind) BatchSize() int { return 1 }

// Send writes one or more encrypted WireGuard packets.  Direct writes are
// attempted first; a failed direct path is retired and the packet is retried
// through the current relay session.
func (b *Bind) Send(bufs [][]byte, ep wgconn.Endpoint) error {
	if b == nil {
		return ErrTransportClosed
	}
	if len(bufs) > b.BatchSize() {
		return fmt.Errorf("wire-connect: Send received %d packets; batch size is %d", len(bufs), b.BatchSize())
	}
	if len(bufs) == 0 {
		return nil
	}
	if _, ok := ep.(*virtualEndpoint); !ok || ep == nil {
		return wgconn.ErrWrongEndpointType
	}
	for _, pkt := range bufs {
		if len(pkt) == 0 || len(pkt) > maxPacketSize {
			return fmt.Errorf("wire-connect: packet size %d outside 1-%d", len(pkt), maxPacketSize)
		}
		if err := b.sendOne(pkt); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bind) sendOne(pkt []byte) error {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()

	b.pathMu.RLock()
	direct := b.direct
	relay := b.relay
	b.pathMu.RUnlock()

	var directErr error
	if direct != nil && direct.conn != nil {
		n, err := direct.conn.Write(pkt)
		if err == nil && n == len(pkt) {
			b.bytesSent.Add(uint64(n))
			return nil
		}
		if err == nil {
			err = io.ErrShortWrite
		}
		directErr = err
		b.dropDirectPath(direct)
	}

	if relay != nil && relay.client != nil {
		_ = relay.nc.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
		err := relay.client.Send(b.peer, pkt)
		_ = relay.nc.SetWriteDeadline(time.Time{})
		if err == nil {
			b.bytesSent.Add(uint64(len(pkt)))
			return nil
		} else {
			directErr = errors.Join(directErr, err)
			// A failed write is a stronger signal than the receive loop's
			// next deadline.  Retire this session immediately so the relay
			// worker can reconnect and a later WireGuard retry can use it.
			b.clearRelay(relay)
			relay.close()
		}
	}

	if b.isShutdown() {
		return ErrTransportClosed
	}
	if directErr != nil {
		return fmt.Errorf("wire-connect: send packet: %w", directErr)
	}
	return ErrNoTransport
}

// SetDirect makes c the preferred datagram path and starts its receive loop.
// Replacing an existing direct path closes the old connection.
func (b *Bind) SetDirect(c net.Conn) error {
	if b == nil {
		return ErrTransportClosed
	}
	if c == nil {
		return errors.New("wire-connect: nil direct connection")
	}
	if b.isShutdown() {
		return ErrTransportClosed
	}
	p := &directPath{conn: c}
	b.pathMu.Lock()
	if b.stopped.Load() {
		b.pathMu.Unlock()
		_ = c.Close()
		return ErrTransportClosed
	}
	old := b.direct
	b.direct = p
	b.pathMu.Unlock()
	if old != nil && old.conn != nil {
		_ = old.conn.Close()
	}

	b.workerMu.Lock()
	if b.workersClosed {
		b.workerMu.Unlock()
		b.dropDirectPath(p)
		return ErrTransportClosed
	}
	b.workers.Add(1)
	b.workerMu.Unlock()
	go b.directReadLoop(p)
	return nil
}

// DropDirect removes and closes the preferred direct path.  Relay reconnects
// continue independently.
func (b *Bind) DropDirect() {
	if b == nil {
		return
	}
	b.pathMu.Lock()
	p := b.direct
	b.direct = nil
	b.pathMu.Unlock()
	if p != nil && p.conn != nil {
		_ = p.conn.Close()
	}
}

// Direct reports whether a direct path is currently selected.
func (b *Bind) Direct() bool {
	if b == nil {
		return false
	}
	b.pathMu.RLock()
	ok := b.direct != nil
	b.pathMu.RUnlock()
	return ok
}

// Stats returns an atomic snapshot of the active path and byte counters.
func (b *Bind) Stats() Stats {
	if b == nil {
		return Stats{Mode: "closed"}
	}
	b.pathMu.RLock()
	direct := b.direct != nil
	relay := b.relay != nil
	b.pathMu.RUnlock()
	mode := "none"
	if direct {
		mode = "direct"
	} else if relay {
		mode = "relay"
	}
	if b.isShutdown() {
		mode = "closed"
	}
	return Stats{
		Mode:           mode,
		Sent:           b.bytesSent.Load(),
		Received:       b.bytesReceived.Load(),
		RelayConnected: relay,
	}
}

// WaitRelay waits until a relay connection is ready.  It observes future
// reconnects as well as the first connection and returns promptly on context
// cancellation.
func (b *Bind) WaitRelay(ctx context.Context) error {
	if b == nil {
		return ErrTransportClosed
	}
	if ctx == nil {
		return errors.New("wire-connect: nil context")
	}
	if b.isShutdown() {
		return ErrTransportClosed
	}
	if b.url == "" {
		return ErrRelayDisabled
	}
	for {
		b.pathMu.RLock()
		connected := b.relay != nil
		wake := b.wake
		b.pathMu.RUnlock()
		if connected {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-b.shutdownCh:
			return ErrTransportClosed
		case <-wake:
		}
	}
}

func (b *Bind) receive(g *receiveGeneration) wgconn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
		if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
			return 0, errors.New("wire-connect: receive callback requires one packet buffer and endpoint")
		}
		for {
			if g.closed() || b.isShutdown() {
				return 0, net.ErrClosed
			}
			select {
			case <-g.done:
				return 0, net.ErrClosed
			case <-b.shutdownCh:
				return 0, net.ErrClosed
			case pkt := <-b.inbound:
				// Close wins over an already-ready queue entry.  This is what
				// guarantees every callback from a closed generation returns
				// net.ErrClosed, even if packets were queued before Close.
				if g.closed() || b.isShutdown() {
					return 0, net.ErrClosed
				}
				if len(pkt) > len(packets[0]) {
					sizes[0] = copy(packets[0], pkt)
					return 0, io.ErrShortBuffer
				}
				sizes[0] = copy(packets[0], pkt)
				eps[0] = b.endpoint
				return 1, nil
			}
		}
	}
}

func (b *Bind) enqueue(pkt []byte) {
	if len(pkt) == 0 || len(pkt) > maxPacketSize || b.isShutdown() {
		return
	}
	copyPkt := make([]byte, len(pkt))
	copy(copyPkt, pkt)
	select {
	case b.inbound <- copyPkt:
		b.bytesReceived.Add(uint64(len(copyPkt)))
	default:
		// A full queue is a deliberate drop policy.  WireGuard retransmits
		// handshake and keepalive packets, and an unbounded queue would let a
		// stalled TUN consumer exhaust process memory.
	}
}

func (b *Bind) directReadLoop(p *directPath) {
	defer b.workers.Done()
	buf := make([]byte, maxPacketSize)
	for {
		n, err := p.conn.Read(buf)
		if n > 0 {
			b.enqueue(buf[:n])
		}
		if err != nil {
			b.dropDirectPath(p)
			return
		}
		if n == 0 {
			b.dropDirectPath(p)
			return
		}
	}
}

func (b *Bind) dropDirectPath(p *directPath) {
	if p == nil {
		return
	}
	b.pathMu.Lock()
	if b.direct == p {
		b.direct = nil
	}
	b.pathMu.Unlock()
	_ = p.conn.Close()
}

func (b *Bind) isShutdown() bool {
	return b.stopped.Load()
}

func (b *Bind) relayLoop() {
	defer b.workers.Done()
	delay := initialReconnectDelay
	for {
		if b.contextDone() {
			return
		}
		session, err := b.dialRelay()
		if err != nil {
			b.debugf("relay connect failed: %v", err)
			if !b.waitReconnect(delay) {
				return
			}
			delay = minDuration(maxReconnectDelay, delay*2)
			continue
		}
		b.replaceRelay(session)
		connectedAt := time.Now()
		err = b.receiveRelay(session)
		b.clearRelay(session)
		session.close()
		if err != nil && !b.contextDone() {
			b.debugf("relay connection ended: %v", err)
		}
		if b.contextDone() {
			return
		}
		if time.Since(connectedAt) >= 5*time.Second {
			delay = initialReconnectDelay
		} else {
			delay = minDuration(maxReconnectDelay, delay*2)
		}
		if !b.waitReconnect(delay) {
			return
		}
	}
}

func (b *Bind) dialRelay() (*relaySession, error) {
	ctx, cancel := context.WithTimeout(b.ctx, relayDialTimeout)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, b.url, &websocket.DialOptions{
		HTTPClient:   b.client,
		Subprotocols: []string{"derp"},
	})
	if err != nil {
		return nil, err
	}
	nc := websocket.NetConn(b.ctx, ws, websocket.MessageBinary)
	brw := bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc))
	client, err := derp.NewClient(b.private, nc, brw, b.derpLogf(), derp.CanAckPings(true))
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	return &relaySession{nc: nc, client: client}, nil
}

func (b *Bind) receiveRelay(s *relaySession) error {
	for {
		msg, err := s.client.Recv()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case derp.ReceivedPacket:
			// A DERP server can be shared by many peers.  A Bind must never
			// inject another peer's packet into this WireGuard instance.
			if m.Source.Compare(b.peer) != 0 {
				continue
			}
			b.enqueue(m.Data)
		case derp.PingMessage:
			var ping [8]byte
			copy(ping[:], m[:])
			if err := s.client.SendPong(ping); err != nil {
				return err
			}
		case derp.ServerRestartingMessage:
			return errors.New("relay server is restarting")
		}
	}
}

func (b *Bind) replaceRelay(s *relaySession) {
	if b.isShutdown() {
		s.close()
		return
	}
	b.pathMu.Lock()
	old := b.relay
	b.relay = s
	b.signalRelayLocked()
	b.pathMu.Unlock()
	if old != nil && old != s {
		old.close()
	}
}

func (b *Bind) clearRelay(s *relaySession) {
	b.pathMu.Lock()
	if b.relay == s {
		b.relay = nil
		b.signalRelayLocked()
	}
	b.pathMu.Unlock()
}

func (b *Bind) signalRelayLocked() {
	close(b.wake)
	b.wake = make(chan struct{})
}

func (b *Bind) contextDone() bool {
	select {
	case <-b.ctx.Done():
		return true
	default:
		return false
	}
}

func (b *Bind) waitReconnect(delay time.Duration) bool {
	delay = jitterDelay(delay)
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-b.ctx.Done():
		return false
	}
}

func (b *Bind) debugf(format string, args ...any) {
	if b.log != nil {
		b.log.Debug(fmt.Sprintf(format, args...))
	}
}

func (b *Bind) derpLogf() func(string, ...any) {
	return func(format string, args ...any) {
		if b.log != nil {
			b.log.Debug(fmt.Sprintf(format, args...))
		}
	}
}

func normalizeRelayURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("wire-connect: invalid relay URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("wire-connect: relay URL scheme must be ws, wss, http, or https")
	}
	if u.Host == "" {
		return "", errors.New("wire-connect: relay URL has no host")
	}
	u.Path = path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
	if u.Path != "/derp" && !strings.HasSuffix(u.Path, "/derp") {
		u.Path = path.Join(u.Path, "derp")
	}
	return u.String(), nil
}

func jitterDelay(base time.Duration) time.Duration {
	if base <= 0 {
		return time.Millisecond
	}
	// Use a small cryptographically-random jitter so a fleet of clients that
	// lost a relay at once does not reconnect in lockstep.  Falling back to the
	// base delay is safe if the system entropy source is temporarily unavailable.
	span := int64(base / 5)
	if span <= 0 {
		return base
	}
	n, err := rand.Int(rand.Reader, big.NewInt(2*span+1))
	if err != nil {
		return base
	}
	return base - time.Duration(span) + time.Duration(n.Int64())
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// virtualEndpoint is intentionally small and immutable.  Its address is only
// used by WireGuard for endpoint bookkeeping and cookie calculations.
type virtualEndpoint struct {
	addr netip.AddrPort
}

var _ wgconn.Endpoint = (*virtualEndpoint)(nil)

func (e *virtualEndpoint) ClearSrc()           {}
func (e *virtualEndpoint) SrcToString() string { return "" }
func (e *virtualEndpoint) DstToString() string { return e.addr.String() }
func (e *virtualEndpoint) DstToBytes() []byte {
	b, _ := e.addr.MarshalBinary()
	return b
}
func (e *virtualEndpoint) DstIP() netip.Addr { return e.addr.Addr() }
func (e *virtualEndpoint) SrcIP() netip.Addr { return netip.Addr{} }
