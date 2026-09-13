package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pionice "github.com/pion/ice/v4"
	wgconn "golang.zx2c4.com/wireguard/conn"
	"tailscale.com/derp/derpserver"
	"tailscale.com/types/key"
)

func TestNormalizeRelayURL(t *testing.T) {
	for _, test := range []struct {
		in, want string
	}{
		{"https://relay.example", "wss://relay.example/derp"},
		{"wss://relay.example/base", "wss://relay.example/base/derp"},
		{"ws://127.0.0.1:1/derp", "ws://127.0.0.1:1/derp"},
	} {
		got, err := normalizeRelayURL(test.in)
		if err != nil {
			t.Fatalf("normalizeRelayURL(%q): %v", test.in, err)
		}
		if got != test.want {
			t.Fatalf("normalizeRelayURL(%q) = %q, want %q", test.in, got, test.want)
		}
	}
	if _, err := normalizeRelayURL("file:///tmp/relay"); err == nil {
		t.Fatal("file URL was accepted as relay")
	}
}

func TestICEHostGuestLocalDatagrams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	host, err := NewICE(ctx, "", true)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := NewICE(ctx, "", false)
	if err != nil {
		host.Close()
		t.Fatal(err)
	}
	defer host.Close()
	defer guest.Close()

	hostOffer, err := host.LocalOffer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	guestOffer, err := guest.LocalOffer(ctx)
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		conn net.Conn
		err  error
	}
	hostResult := make(chan result, 1)
	guestResult := make(chan result, 1)
	go func() {
		conn, err := host.Connect(ctx, guestOffer)
		hostResult <- result{conn: conn, err: err}
	}()
	go func() {
		conn, err := guest.Connect(ctx, hostOffer)
		guestResult <- result{conn: conn, err: err}
	}()
	hostConn := <-hostResult
	guestConn := <-guestResult
	if hostConn.err != nil {
		t.Fatalf("host connect: %v", hostConn.err)
	}
	if guestConn.err != nil {
		t.Fatalf("guest connect: %v", guestConn.err)
	}
	defer hostConn.conn.Close()
	defer guestConn.conn.Close()

	payload := []byte("ice datagram")
	if n, err := hostConn.conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write = %d, %v", n, err)
	}
	if err := guestConn.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 64)
	n, err := guestConn.conn.Read(got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("payload = %q, want %q", got[:n], payload)
	}
}

func TestICEConnectAttemptCancellationKeepsConnectedConn(t *testing.T) {
	root, cancelRoot := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelRoot()
	host, err := NewICE(root, "", true)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := NewICE(root, "", false)
	if err != nil {
		_ = host.Close()
		t.Fatal(err)
	}
	defer host.Close()
	defer guest.Close()

	hostOffer, err := host.LocalOffer(root)
	if err != nil {
		t.Fatal(err)
	}
	guestOffer, err := guest.LocalOffer(root)
	if err != nil {
		t.Fatal(err)
	}

	attemptCtx, cancelAttempt := context.WithTimeout(root, 5*time.Second)
	type connectResult struct {
		conn net.Conn
		err  error
	}
	hostResult := make(chan connectResult, 1)
	guestResult := make(chan connectResult, 1)
	go func() {
		conn, err := host.Connect(attemptCtx, guestOffer)
		hostResult <- connectResult{conn: conn, err: err}
	}()
	go func() {
		conn, err := guest.Connect(attemptCtx, hostOffer)
		guestResult <- connectResult{conn: conn, err: err}
	}()
	hostConn := <-hostResult
	guestConn := <-guestResult
	if hostConn.err != nil {
		t.Fatalf("host connect: %v", hostConn.err)
	}
	if guestConn.err != nil {
		t.Fatalf("guest connect: %v", guestConn.err)
	}
	defer hostConn.conn.Close()
	defer guestConn.conn.Close()

	// Client code cancels this short attempt context immediately after
	// Connect returns. The ICE agent has its own root lifetime, so the
	// selected pair and its packet buffer must remain usable.
	cancelAttempt()
	payload := []byte("after attempt cancellation")
	if n, err := hostConn.conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write after attempt cancellation = %d, %v", n, err)
	}
	if err := guestConn.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 128)
	n, err := guestConn.conn.Read(got)
	if err != nil {
		t.Fatalf("read after attempt cancellation: %v", err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("payload after attempt cancellation = %q, want %q", got[:n], payload)
	}
}

func TestICEConsentLossUnblocksRead(t *testing.T) {
	root, cancelRoot := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelRoot()
	host, guest, hostConn, guestConn := connectedICEPair(t, root)
	defer host.Close()
	defer guest.Close()
	defer hostConn.Close()
	defer guestConn.Close()

	readResult := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		_, err := hostConn.Read(buf)
		readResult <- err
	}()
	// Give Read time to enter Pion's packet buffer. This invokes the same
	// callback that Pion uses when consent freshness reports a disconnected
	// or failed state, and verifies that the monitored Conn closes it.
	time.Sleep(20 * time.Millisecond)
	host.handleConnectionState(pionice.ConnectionStateDisconnected)
	select {
	case err := <-readResult:
		if err == nil {
			t.Fatal("Read returned nil after ICE consent loss")
		}
	case <-time.After(time.Second):
		t.Fatal("Read remained blocked after ICE consent loss")
	}
}

func TestICERealConsentLossUnblocksRead(t *testing.T) {
	root, cancelRoot := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelRoot()
	timing := iceTiming{
		keepalive:    50 * time.Millisecond,
		disconnected: 500 * time.Millisecond,
		failed:       0,
		stunGather:   3 * time.Second,
	}
	host, guest, hostConn, guestConn := connectedICEPairWithTiming(t, root, timing)
	defer host.Close()
	defer guest.Close()
	defer hostConn.Close()
	defer guestConn.Close()

	readResult := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		_, err := hostConn.Read(buf)
		readResult <- err
	}()
	if err := guest.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readResult:
		if err == nil {
			t.Fatal("Read returned nil after real ICE consent loss")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("Read remained blocked after real ICE consent loss")
	}
}

func TestICELocalOfferCancellationAndBounds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	i, err := NewICE(ctx, "", true)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	canceled, cancelOffer := context.WithCancel(context.Background())
	cancelOffer()
	if _, err := i.LocalOffer(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("LocalOffer error = %v, want context.Canceled", err)
	}
	cancel()
	select {
	case <-i.closeDone:
	case <-time.After(time.Second):
		t.Fatal("ICE context cancellation did not close agent")
	}
	if _, err := i.LocalOffer(context.Background()); !errors.Is(err, ErrICEClosed) {
		t.Fatalf("closed LocalOffer error = %v, want ErrICEClosed", err)
	}
}

func TestICEExcludedIPsFilterLocalAndRemoteCandidates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	virtualLocal := netip.MustParseAddr("100.64.0.1")
	virtualPeer := netip.MustParseAddr("100.64.0.2")
	loopbackV4 := netip.MustParseAddr("127.0.0.1")
	loopbackV6 := netip.MustParseAddr("::1")
	excluded := []netip.Addr{virtualLocal, virtualPeer, loopbackV4, loopbackV6}

	local, err := NewICE(ctx, "", true, excluded...)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	offer, err := local.LocalOffer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range offer.Candidates {
		candidate, err := pionice.UnmarshalCandidate(raw)
		if err != nil {
			t.Fatal(err)
		}
		addr, err := netip.ParseAddr(candidate.Address())
		if err != nil {
			t.Fatal(err)
		}
		for _, blocked := range excluded {
			if addr.Unmap() == blocked.Unmap() {
				t.Fatalf("excluded local address %s appeared in candidate %q", blocked, raw)
			}
		}
	}

	remoteCandidate, err := pionice.NewCandidateHost(&pionice.CandidateHostConfig{
		Network:   "udp4",
		Address:   virtualPeer.String(),
		Port:      40000,
		Component: pionice.ComponentRTP,
		Priority:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	remote := Offer{Ufrag: "remote-ufrag", Password: "remote-password", Candidates: []string{remoteCandidate.Marshal()}}
	remoteFiltered, err := NewICE(ctx, "", true, virtualPeer)
	if err != nil {
		t.Fatal(err)
	}
	defer remoteFiltered.Close()
	if _, err := remoteFiltered.Connect(ctx, remote); err == nil || !strings.Contains(err.Error(), "no usable candidates after IP filtering") {
		t.Fatalf("Connect excluded remote candidate error = %v", err)
	}
}

func TestBindDirectReceiveCloseReopenAndFallback(t *testing.T) {
	private := key.NewNode()
	b, err := New(context.Background(), RelayConfig{Private: private, Peer: key.NewNode().Public()})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Shutdown()

	fns, port, err := b.Open(51820)
	if err != nil {
		t.Fatal(err)
	}
	if port != 1 || len(fns) != 1 || b.BatchSize() != 1 {
		t.Fatalf("Open = %d ports, %d callbacks, batch %d", port, len(fns), b.BatchSize())
	}
	ep, err := b.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if got := ep.DstToString(); got != "127.0.0.1:1" {
		t.Fatalf("virtual endpoint = %q, want 127.0.0.1:1", got)
	}
	left, right := net.Pipe()
	if err := b.SetDirect(left); err != nil {
		t.Fatal(err)
	}
	payload := []byte("direct packet")
	if _, err := right.Write(payload); err != nil {
		t.Fatal(err)
	}
	sizes := make([]int, 1)
	// Use the concrete WireGuard callback signature through the helper below;
	// keeping the receive assertion in one place makes Close's wake-up test
	// easier to read.
	got, err := readBindPacketWithin(fns[0], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("direct receive = %q, want %q", got, payload)
	}

	payload = []byte("outbound packet")
	readDone := make(chan []byte, 1)
	go func() {
		got := make([]byte, 128)
		n, _ := right.Read(got)
		readDone <- got[:n]
	}()
	if err := b.Send([][]byte{payload}, ep); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-readDone:
		if string(got) != string(payload) {
			t.Fatalf("direct send = %q, want %q", got, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("direct send did not reach peer")
	}

	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() {
		_, err := fns[0]([][]byte{make([]byte, 128)}, sizes, make([]wgconn.Endpoint, 1))
		closed <- err
	}()
	select {
	case err := <-closed:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed callback error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closed callback remained blocked")
	}

	fns, _, err = b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.SetDirect(right); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBindRelayWebSocketAndSourceFiltering(t *testing.T) {
	serverKey := key.NewNode()
	server := derpserver.New(serverKey, func(string, ...any) {})
	httpServer := httptest.NewServer(derpserver.AddWebSocketSupport(server, http.NotFoundHandler()))
	defer httpServer.Close()
	defer server.Close()

	privateA := key.NewNode()
	privateB := key.NewNode()
	privateC := key.NewNode()
	a, err := New(context.Background(), RelayConfig{URL: httpServer.URL, Private: privateA, Peer: privateB.Public()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(context.Background(), RelayConfig{URL: httpServer.URL, Private: privateB, Peer: privateA.Public()})
	if err != nil {
		a.Shutdown()
		t.Fatal(err)
	}
	c, err := New(context.Background(), RelayConfig{URL: httpServer.URL, Private: privateC, Peer: privateB.Public()})
	if err != nil {
		a.Shutdown()
		b.Shutdown()
		t.Fatal(err)
	}
	defer a.Shutdown()
	defer b.Shutdown()
	defer c.Shutdown()
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, bind := range []*Bind{a, b, c} {
		if err := bind.WaitRelay(waitCtx); err != nil {
			t.Fatalf("WaitRelay: %v", err)
		}
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := a.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("relay packet")
	if err := a.Send([][]byte{payload}, ep); err != nil {
		t.Fatal(err)
	}
	got, err := readBindPacketWithin(fns[0], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("relay receive = %q, want %q", got, payload)
	}

	// C is connected to the same DERP server but is not B's configured peer;
	// B must drop its packet before it reaches the WireGuard receive callback.
	if err := c.Send([][]byte{[]byte("unauthorized")}, ep); err != nil {
		t.Fatal(err)
	}
	noPacket := make(chan error, 1)
	go func() {
		_, err := fns[0]([][]byte{make([]byte, 128)}, make([]int, 1), make([]wgconn.Endpoint, 1))
		noPacket <- err
	}()
	select {
	case err := <-noPacket:
		t.Fatalf("unauthorized relay packet result = %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-noPacket:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("filtered callback error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("filtered callback did not close")
	}
}

func TestBindDirectFailureFallsBackRelayReconnectsAndShutsDown(t *testing.T) {
	serverKey := key.NewNode()
	derpServer := derpserver.New(serverKey, func(string, ...any) {})
	var relayAccepts atomic.Uint64
	var activeMu sync.Mutex
	activeConns := make(map[net.Conn]struct{})
	base := derpserver.AddWebSocketSupport(derpServer, http.NotFoundHandler())
	httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/derp" && r.Header.Get("Upgrade") == "websocket" {
			relayAccepts.Add(1)
		}
		base.ServeHTTP(w, r)
	}))
	httpServer.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		activeMu.Lock()
		defer activeMu.Unlock()
		switch state {
		case http.StateNew, http.StateActive, http.StateIdle, http.StateHijacked:
			activeConns[conn] = struct{}{}
		case http.StateClosed:
			delete(activeConns, conn)
		}
	}
	httpServer.Start()
	defer httpServer.Close()
	defer derpServer.Close()

	privateA := key.NewNode()
	privateB := key.NewNode()
	a, err := New(context.Background(), RelayConfig{URL: httpServer.URL, Private: privateA, Peer: privateB.Public()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(context.Background(), RelayConfig{URL: httpServer.URL, Private: privateB, Peer: privateA.Public()})
	if err != nil {
		_ = a.Shutdown()
		t.Fatal(err)
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.WaitRelay(waitCtx); err != nil {
		_ = b.Shutdown()
		_ = a.Shutdown()
		t.Fatalf("A WaitRelay: %v", err)
	}
	if err := b.WaitRelay(waitCtx); err != nil {
		_ = b.Shutdown()
		_ = a.Shutdown()
		t.Fatalf("B WaitRelay: %v", err)
	}
	initialAccepts := relayAccepts.Load()
	if initialAccepts < 2 {
		_ = b.Shutdown()
		_ = a.Shutdown()
		t.Fatalf("relay accepts = %d, want both clients", initialAccepts)
	}

	callbacks, _, err := b.Open(0)
	if err != nil {
		_ = b.Shutdown()
		_ = a.Shutdown()
		t.Fatal(err)
	}
	ep, err := a.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		_ = b.Shutdown()
		_ = a.Shutdown()
		t.Fatal(err)
	}

	// Establish and use a real net.Conn as the preferred direct path. Closing
	// its peer then makes the next direct Write fail, forcing Bind to retry via
	// the still-live DERP session.
	direct, directPeer := net.Pipe()
	if err := a.SetDirect(direct); err != nil {
		_ = directPeer.Close()
		_ = b.Shutdown()
		_ = a.Shutdown()
		t.Fatal(err)
	}
	directRead := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 128)
		n, err := directPeer.Read(buf)
		if err == nil {
			directRead <- append([]byte(nil), buf[:n]...)
		}
	}()
	directPayload := []byte("direct before failure")
	if err := a.Send([][]byte{directPayload}, ep); err != nil {
		_ = directPeer.Close()
		_ = b.Shutdown()
		_ = a.Shutdown()
		t.Fatalf("direct send: %v", err)
	}
	select {
	case got := <-directRead:
		if string(got) != string(directPayload) {
			t.Fatalf("direct payload = %q, want %q", got, directPayload)
		}
	case <-time.After(time.Second):
		t.Fatal("direct packet did not reach direct peer")
	}
	_ = directPeer.Close()
	waitUntil(t, time.Second, func() bool { return !a.Direct() })

	relayPayload := []byte("relay after direct failure")
	if err := a.Send([][]byte{relayPayload}, ep); err != nil {
		_ = b.Shutdown()
		_ = a.Shutdown()
		t.Fatalf("relay fallback send: %v", err)
	}
	got, err := readBindPacketWithin(callbacks[0], time.Second)
	if err != nil {
		_ = b.Shutdown()
		_ = a.Shutdown()
		t.Fatalf("relay fallback receive: %v", err)
	}
	if string(got) != string(relayPayload) {
		t.Fatalf("relay fallback payload = %q, want %q", got, relayPayload)
	}
	if stats := a.Stats(); stats.Mode != "relay" || !stats.RelayConnected {
		t.Fatalf("fallback stats = %+v, want relay", stats)
	}

	// Drop every active WebSocket and require fresh handshakes from both
	// workers. A successful post-reconnect packet proves the new sessions are
	// usable rather than merely reported as connected.
	activeMu.Lock()
	connections := make([]net.Conn, 0, len(activeConns))
	for conn := range activeConns {
		connections = append(connections, conn)
	}
	activeMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	waitUntil(t, 5*time.Second, func() bool { return relayAccepts.Load() >= initialAccepts+2 })
	waitUntil(t, 5*time.Second, func() bool { return a.Stats().RelayConnected && b.Stats().RelayConnected })
	reconnectedPayload := []byte("relay after reconnect")
	if err := a.Send([][]byte{reconnectedPayload}, ep); err != nil {
		_ = b.Shutdown()
		_ = a.Shutdown()
		t.Fatalf("post-reconnect send: %v", err)
	}
	got, err = readBindPacketWithin(callbacks[0], time.Second)
	if err != nil {
		_ = b.Shutdown()
		_ = a.Shutdown()
		t.Fatalf("post-reconnect receive: %v", err)
	}
	if string(got) != string(reconnectedPayload) {
		t.Fatalf("post-reconnect payload = %q, want %q", got, reconnectedPayload)
	}

	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readBindPacketWithin(callbacks[0], time.Second); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed receive callback error = %v, want net.ErrClosed", err)
	}
	if err := b.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if err := b.Shutdown(); err != nil {
		t.Fatal(err)
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err := a.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if err := a.WaitRelay(shutdownCtx); !errors.Is(err, ErrTransportClosed) {
		t.Fatalf("WaitRelay after Shutdown = %v, want ErrTransportClosed", err)
	}
	if _, _, err := a.Open(0); !errors.Is(err, ErrTransportClosed) {
		t.Fatalf("Open after Shutdown = %v, want ErrTransportClosed", err)
	}
}

func TestBindICEConsentLossFallsBackToRelay(t *testing.T) {
	serverKey := key.NewNode()
	derpServer := derpserver.New(serverKey, func(string, ...any) {})
	httpServer := httptest.NewServer(derpserver.AddWebSocketSupport(derpServer, http.NotFoundHandler()))
	defer httpServer.Close()
	defer derpServer.Close()

	privateA := key.NewNode()
	privateB := key.NewNode()
	a, err := New(context.Background(), RelayConfig{URL: httpServer.URL, Private: privateA, Peer: privateB.Public()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(context.Background(), RelayConfig{URL: httpServer.URL, Private: privateB, Peer: privateA.Public()})
	if err != nil {
		_ = a.Shutdown()
		t.Fatal(err)
	}
	defer a.Shutdown()
	defer b.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.WaitRelay(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.WaitRelay(ctx); err != nil {
		t.Fatal(err)
	}
	callbacks, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := a.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}

	timing := iceTiming{
		keepalive:    50 * time.Millisecond,
		disconnected: 500 * time.Millisecond,
		failed:       0,
		stunGather:   3 * time.Second,
	}
	hostICE, guestICE, hostConn, guestConn := connectedICEPairWithTiming(t, ctx, timing)
	defer hostICE.Close()
	defer guestICE.Close()
	if err := a.SetDirect(hostConn); err != nil {
		_ = hostConn.Close()
		_ = guestConn.Close()
		t.Fatal(err)
	}
	if err := b.SetDirect(guestConn); err != nil {
		a.DropDirect()
		t.Fatal(err)
	}

	// Closing the real remote ICE agent removes consent responses. The host's
	// Pion state machine must close the monitored Conn, allowing Bind to retire
	// its direct path and use the already-connected DERP session.
	if err := guestICE.Close(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 2*time.Second, func() bool { return !a.Direct() })
	payload := []byte("relay after ICE consent loss")
	if err := a.Send([][]byte{payload}, ep); err != nil {
		t.Fatal(err)
	}
	got, err := readBindPacketWithin(callbacks[0], time.Second)
	if err != nil {
		t.Fatalf("relay receive after ICE consent loss: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("relay payload after ICE consent loss = %q, want %q", got, payload)
	}
	if stats := a.Stats(); stats.Mode != "relay" {
		t.Fatalf("A stats after ICE consent loss = %+v, want relay", stats)
	}
}

func connectedICEPair(t *testing.T, ctx context.Context) (*ICE, *ICE, net.Conn, net.Conn) {
	return connectedICEPairWithTiming(t, ctx, defaultICETiming)
}

func connectedICEPairWithTiming(t *testing.T, ctx context.Context, timing iceTiming) (*ICE, *ICE, net.Conn, net.Conn) {
	t.Helper()
	host, err := newICE(ctx, "", true, timing)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := newICE(ctx, "", false, timing)
	if err != nil {
		_ = host.Close()
		t.Fatal(err)
	}
	hostOffer, err := host.LocalOffer(ctx)
	if err != nil {
		_ = guest.Close()
		_ = host.Close()
		t.Fatal(err)
	}
	guestOffer, err := guest.LocalOffer(ctx)
	if err != nil {
		_ = guest.Close()
		_ = host.Close()
		t.Fatal(err)
	}
	type connectResult struct {
		conn net.Conn
		err  error
	}
	hostResult := make(chan connectResult, 1)
	guestResult := make(chan connectResult, 1)
	go func() {
		conn, err := host.Connect(ctx, guestOffer)
		hostResult <- connectResult{conn: conn, err: err}
	}()
	go func() {
		conn, err := guest.Connect(ctx, hostOffer)
		guestResult <- connectResult{conn: conn, err: err}
	}()
	hostConn := <-hostResult
	guestConn := <-guestResult
	if hostConn.err != nil || guestConn.err != nil {
		if hostConn.conn != nil {
			_ = hostConn.conn.Close()
		}
		if guestConn.conn != nil {
			_ = guestConn.conn.Close()
		}
		_ = guest.Close()
		_ = host.Close()
		t.Fatalf("connect ICE pair: host=%v guest=%v", hostConn.err, guestConn.err)
	}
	return host, guest, hostConn.conn, guestConn.conn
}

func readBindPacketWithin(fn wgconn.ReceiveFunc, timeout time.Duration) ([]byte, error) {
	type result struct {
		packet []byte
		err    error
	}
	resultCh := make(chan result, 1)
	go func() {
		buf := make([]byte, 65535)
		sizes := make([]int, 1)
		endpoints := make([]wgconn.Endpoint, 1)
		n, err := fn([][]byte{buf}, sizes, endpoints)
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		if n != 1 {
			resultCh <- result{err: fmt.Errorf("receive count = %d, want 1", n)}
			return
		}
		resultCh <- result{packet: append([]byte(nil), buf[:sizes[0]]...)}
	}()
	select {
	case result := <-resultCh:
		return result.packet, result.err
	case <-time.After(timeout):
		return nil, context.DeadlineExceeded
	}
}

func waitUntil(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true before timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
