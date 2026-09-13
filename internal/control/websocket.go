package control

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// wsPeer owns one WebSocket and serializes all writes through a bounded queue.
// A peer's callbacks never run while Server.mu is held.
type wsPeer struct {
	conn *websocket.Conn
	send chan []byte
	done chan struct{}
	rate *tokenBucket

	stopOnce sync.Once
	wg       sync.WaitGroup

	onMessage func([]byte)
}

func newWSPeer(conn *websocket.Conn) *wsPeer {
	conn.SetReadLimit(maxMessageBytes)
	return &wsPeer{
		conn: conn,
		send: make(chan []byte, messageQueueSize),
		done: make(chan struct{}),
		rate: newTokenBucket(32, 64),
	}
}

func (p *wsPeer) start(parent context.Context, onMessage func([]byte), onClose func()) {
	ctx, cancel := context.WithCancel(parent)
	// Set the callback before starting the reader.  start is called only after
	// the peer has been put into its room/pair slot, so the callback sees a
	// fully initialized identity binding.
	p.onMessage = onMessage
	p.wg.Add(3)
	go p.readLoop(ctx)
	go p.writeLoop(ctx)
	go p.pingLoop(ctx)
	go func() {
		select {
		case <-p.done:
		case <-ctx.Done():
			p.stop()
		}
		cancel()
		_ = p.conn.CloseNow()
		p.wg.Wait()
		onClose()
	}()
}

func (p *wsPeer) stop() {
	p.stopOnce.Do(func() {
		close(p.done)
		_ = p.conn.CloseNow()
	})
}

func (p *wsPeer) stopped() bool {
	if p == nil {
		return true
	}
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *wsPeer) enqueue(data []byte) bool {
	if len(data) > maxMessageBytes {
		return false
	}
	copyData := append([]byte(nil), data...)
	select {
	case <-p.done:
		return false
	default:
	}
	select {
	case p.send <- copyData:
		return true
	case <-p.done:
		return false
	default:
		// A peer that cannot drain a small bounded queue is unhealthy.  Close
		// it rather than allowing unbounded memory growth.
		p.stop()
		return false
	}
}

func (p *wsPeer) readLoop(ctx context.Context) {
	defer p.wg.Done()
	for {
		typ, data, err := p.conn.Read(ctx)
		if err != nil {
			p.stop()
			return
		}
		if !p.rate.allow() {
			p.stop()
			return
		}
		if typ != websocket.MessageText && typ != websocket.MessageBinary {
			p.stop()
			return
		}
		if len(data) > maxMessageBytes || !validClientMessage(data) {
			p.stop()
			return
		}
		if p.onMessage != nil {
			p.onMessage(data)
		}
	}
}

func (p *wsPeer) writeLoop(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.done:
			return
		case data := <-p.send:
			writeCtx, cancel := context.WithTimeout(ctx, websocketWriteTimeout)
			err := p.conn.Write(writeCtx, websocket.MessageText, data)
			cancel()
			if err != nil {
				p.stop()
				return
			}
		}
	}
}

func (p *wsPeer) pingLoop(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(websocketPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.done:
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, websocketPingTimeout)
			err := p.conn.Ping(pingCtx)
			cancel()
			if err != nil {
				p.stop()
				return
			}
		}
	}
}

func validClientMessage(data []byte) bool {
	if len(data) == 0 || len(data) > maxMessageBytes {
		return false
	}
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return false
	}
	if msg.Kind != "pake" && msg.Kind != "sealed" {
		return false
	}
	if len(msg.Payload) == 0 || !json.Valid(msg.Payload) {
		return false
	}
	return true
}

func peerEvent(connected bool) []byte {
	payload, _ := json.Marshal(struct {
		Connected bool `json:"connected"`
	}{Connected: connected})
	data, _ := json.Marshal(Message{Kind: "peer", Payload: payload})
	return data
}

// tokenBucket limits application data frames per connection to 32 per second
// with a burst of 64.  It protects the server's JSON parser and forwarding
// path while leaving enough room for the short PAKE/ICE exchange.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(ratePerSecond, burst int) *tokenBucket {
	now := time.Now()
	return &tokenBucket{rate: float64(ratePerSecond), burst: float64(burst), tokens: float64(burst), last: now}
}

func (b *tokenBucket) allow() bool {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
