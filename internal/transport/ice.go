package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	pionice "github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
)

const (
	maxOfferCredentialLen = 256
	maxOfferCandidates    = 64
	maxOfferCandidateLen  = 1024
	maxOfferBytes         = 24 << 10
	iceGatherTimeout      = 8 * time.Second
)

var (
	ErrICEClosed  = errors.New("wire-connect: ICE agent is closed")
	ErrICEStarted = errors.New("wire-connect: ICE connection has already been started")
)

type iceTiming struct {
	keepalive    time.Duration
	disconnected time.Duration
	failed       time.Duration
	stunGather   time.Duration
}

var defaultICETiming = iceTiming{
	keepalive:    2 * time.Second,
	disconnected: 15 * time.Second,
	failed:       30 * time.Second,
	stunGather:   3 * time.Second,
}

// Offer is the signaling data needed by another ICE agent.  Candidates are
// complete, serialized Pion candidates; the caller can safely JSON encode the
// value without retaining any Pion objects.
type Offer struct {
	Ufrag      string   `json:"ufrag"`
	Password   string   `json:"password"`
	Candidates []string `json:"candidates"`
}

// ICE wraps a Pion ICE agent with bounded signaling data and an explicit role.
// host controls the ICE role: a host is controlling and calls Dial, while a
// guest is controlled and calls Accept.
type ICE struct {
	ctx    context.Context
	cancel context.CancelFunc
	agent  *pionice.Agent
	host   bool
	// excludedIPs is immutable after construction. It protects both local
	// candidate gathering and remote candidate admission from selecting the
	// virtual tunnel addresses as outer ICE endpoints.
	excludedIPs map[netip.Addr]struct{}

	mu             sync.Mutex
	closed         bool
	gatherStarted  bool
	connectStarted bool

	gatherDone chan struct{}
	gatherOnce sync.Once
	lost       chan struct{}
	lostOnce   sync.Once
	closeOnce  sync.Once
	closeDone  chan struct{}
	closeErr   error
}

// NewICE constructs an agent and returns immediately. stunURL may be empty
// for host-candidate-only operation or a stun:// / stuns:// URI. mDNS and TCP
// candidates are disabled because this transport only carries UDP datagrams;
// loopback is retained to make local and deterministic tests possible.
//
// excludedIPs optionally lists addresses that must never be used as local or
// remote ICE candidates. Callers that create a virtual interface should pass
// both virtual tunnel addresses here; doing so prevents ICE from selecting a
// route through the tunnel itself and recursively carrying its own outer
// traffic. The arguments are normalized with Addr.Unmap and are also applied
// to peer-reflexive candidates discovered during connectivity checks.
func NewICE(ctx context.Context, stunURL string, host bool, excludedIPs ...netip.Addr) (*ICE, error) {
	return newICE(ctx, stunURL, host, defaultICETiming, excludedIPs...)
}

func newICE(ctx context.Context, stunURL string, host bool, timing iceTiming, excludedIPs ...netip.Addr) (*ICE, error) {
	if ctx == nil {
		return nil, errors.New("wire-connect: nil context")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	excluded, err := normalizeExcludedIPs(excludedIPs)
	if err != nil {
		return nil, err
	}

	var urls []*stun.URI
	if strings.TrimSpace(stunURL) != "" {
		u, err := stun.ParseURI(strings.TrimSpace(stunURL))
		if err != nil {
			return nil, fmt.Errorf("wire-connect: invalid STUN URL: %w", err)
		}
		if u.Scheme != stun.SchemeTypeSTUN && u.Scheme != stun.SchemeTypeSTUNS {
			return nil, fmt.Errorf("wire-connect: STUN URL must use stun or stuns scheme")
		}
		urls = []*stun.URI{u}
	}

	options := []pionice.AgentOption{
		pionice.WithUrls(urls),
		pionice.WithNetworkTypes([]pionice.NetworkType{
			pionice.NetworkTypeUDP4,
			pionice.NetworkTypeUDP6,
		}),
		pionice.WithCandidateTypes([]pionice.CandidateType{
			pionice.CandidateTypeHost,
			pionice.CandidateTypeServerReflexive,
		}),
		pionice.WithMulticastDNSMode(pionice.MulticastDNSModeDisabled),
		pionice.WithIncludeLoopback(),
		pionice.WithDisableActiveTCP(),
		pionice.WithKeepaliveInterval(timing.keepalive),
		pionice.WithDisconnectedTimeout(timing.disconnected),
		pionice.WithFailedTimeout(timing.failed),
		pionice.WithSTUNGatherTimeout(timing.stunGather),
	}
	if len(excluded) > 0 {
		// Pion applies IPFilter while gathering host candidates and
		// RemoteIPFilter both to signaled candidates and to peer-reflexive
		// candidates created from authenticated STUN requests.
		keep := func(ip net.IP) bool { return !excludedIP(excluded, ip) }
		options = append(options, pionice.WithIPFilter(keep), pionice.WithRemoteIPFilter(keep))
	}
	agent, err := pionice.NewAgentWithOptions(options...)
	if err != nil {
		return nil, fmt.Errorf("wire-connect: create ICE agent: %w", err)
	}

	iceCtx, cancel := context.WithCancel(ctx)
	i := &ICE{
		ctx:         iceCtx,
		cancel:      cancel,
		agent:       agent,
		host:        host,
		excludedIPs: excluded,
		gatherDone:  make(chan struct{}),
		lost:        make(chan struct{}),
		closeDone:   make(chan struct{}),
	}
	if err := agent.OnCandidate(func(candidate pionice.Candidate) {
		// Pion invokes the callback with nil when gathering is complete.  The
		// callback is deliberately independent of LocalOffer's context: a
		// caller may cancel one wait and still safely close or inspect the
		// agent later.
		//
		// Candidate values themselves are obtained from GetLocalCandidates
		// after this notification, avoiding aliasing callback-owned objects.
		//
		// The callback may run after Close, so gatherOnce is the only state it
		// touches.
		if candidate == nil {
			i.gatherOnce.Do(func() { close(i.gatherDone) })
		}
	}); err != nil {
		cancel()
		_ = agent.Close()
		return nil, fmt.Errorf("wire-connect: register ICE candidate handler: %w", err)
	}
	if err := agent.OnConnectionStateChange(i.handleConnectionState); err != nil {
		cancel()
		_ = agent.Close()
		return nil, fmt.Errorf("wire-connect: register ICE state handler: %w", err)
	}

	// The context watcher owns cancellation initiated by the caller.  It is
	// not exposed as a worker and never waits on itself.
	go func() {
		<-iceCtx.Done()
		_ = i.Close()
	}()
	return i, nil
}

// handleConnectionState turns Pion's terminal and consent-loss states into a
// one-shot signal for every connection returned by this single-use agent. A
// Pion Conn can otherwise remain blocked in its packet buffer after consent
// expires, so monitoredICEConn uses this signal to close the underlying Conn
// and unblock Bind's direct read loop.
func (i *ICE) handleConnectionState(state pionice.ConnectionState) {
	switch state {
	case pionice.ConnectionStateDisconnected, pionice.ConnectionStateFailed, pionice.ConnectionStateClosed:
		i.lostOnce.Do(func() { close(i.lost) })
	}
}

// LocalOffer starts candidate gathering once and waits for completion.  The
// internal eight-second cap prevents a broken STUN server from hanging a
// command indefinitely; a caller's shorter deadline still wins.
func (i *ICE) LocalOffer(ctx context.Context) (Offer, error) {
	if i == nil {
		return Offer{}, ErrICEClosed
	}
	if ctx == nil {
		return Offer{}, errors.New("wire-connect: nil context")
	}
	select {
	case <-ctx.Done():
		return Offer{}, ctx.Err()
	default:
	}

	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return Offer{}, ErrICEClosed
	}
	start := !i.gatherStarted
	if start {
		i.gatherStarted = true
	}
	gatherDone := i.gatherDone
	i.mu.Unlock()

	if start {
		if err := i.agent.GatherCandidates(); err != nil {
			return Offer{}, fmt.Errorf("wire-connect: gather ICE candidates: %w", err)
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, iceGatherTimeout)
	defer cancel()
	select {
	case <-gatherDone:
	case <-waitCtx.Done():
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Offer{}, ctx.Err()
		}
		if errors.Is(i.ctx.Err(), context.Canceled) {
			return Offer{}, ErrICEClosed
		}
		return Offer{}, fmt.Errorf("wire-connect: gather ICE candidates: %w", context.DeadlineExceeded)
	}

	i.mu.Lock()
	closed := i.closed
	i.mu.Unlock()
	if closed {
		return Offer{}, ErrICEClosed
	}
	ufrag, password, err := i.agent.GetLocalUserCredentials()
	if err != nil {
		return Offer{}, fmt.Errorf("wire-connect: get ICE credentials: %w", err)
	}
	candidates, err := i.agent.GetLocalCandidates()
	if err != nil {
		return Offer{}, fmt.Errorf("wire-connect: get ICE candidates: %w", err)
	}
	if len(candidates) > maxOfferCandidates {
		return Offer{}, fmt.Errorf("wire-connect: ICE candidate count %d exceeds %d", len(candidates), maxOfferCandidates)
	}
	offer := Offer{Ufrag: ufrag, Password: password, Candidates: make([]string, 0, len(candidates))}
	totalCandidateBytes := 0
	for _, candidate := range candidates {
		if candidate == nil || !allowedCandidate(candidate) || i.isExcludedCandidate(candidate) {
			continue
		}
		raw := candidate.Marshal()
		if len(raw) == 0 || len(raw) > maxOfferCandidateLen {
			return Offer{}, fmt.Errorf("wire-connect: ICE candidate exceeds %d bytes", maxOfferCandidateLen)
		}
		totalCandidateBytes += len(raw)
		if totalCandidateBytes > maxOfferBytes {
			return Offer{}, fmt.Errorf("wire-connect: ICE offer exceeds %d bytes", maxOfferBytes)
		}
		offer.Candidates = append(offer.Candidates, raw)
	}
	if err := validateCredentials(offer.Ufrag, offer.Password); err != nil {
		return Offer{}, fmt.Errorf("wire-connect: invalid local ICE credentials: %w", err)
	}
	return offer, nil
}

// Connect applies a remote offer and waits for the nominated UDP candidate
// pair.  The Pion agent is single-use by design; after a failed attempt the
// caller should create a fresh ICE value for a restart.
func (i *ICE) Connect(ctx context.Context, remote Offer) (net.Conn, error) {
	if i == nil {
		return nil, ErrICEClosed
	}
	if ctx == nil {
		return nil, errors.New("wire-connect: nil context")
	}
	if err := validateOffer(remote); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	parsedCandidates := make([]pionice.Candidate, 0, len(remote.Candidates))
	for _, raw := range remote.Candidates {
		candidate, err := pionice.UnmarshalCandidate(raw)
		if err != nil {
			return nil, fmt.Errorf("wire-connect: parse remote ICE candidate: %w", err)
		}
		// Validate again after parsing.  Keeping this check next to the
		// AddRemoteCandidate call prevents future refactors from accidentally
		// accepting TCP, mDNS, or unsupported candidate types.
		if !allowedCandidate(candidate) {
			return nil, errors.New("wire-connect: remote offer contains a non-UDP candidate")
		}
		if i.isExcludedCandidate(candidate) {
			continue
		}
		duplicate := false
		for _, existing := range parsedCandidates {
			if candidate.Equal(existing) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			parsedCandidates = append(parsedCandidates, candidate)
		}
	}
	if len(parsedCandidates) == 0 {
		return nil, errors.New("wire-connect: remote ICE offer has no usable candidates after IP filtering")
	}

	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return nil, ErrICEClosed
	}
	if i.connectStarted {
		i.mu.Unlock()
		return nil, ErrICEStarted
	}
	i.connectStarted = true
	i.mu.Unlock()

	for _, candidate := range parsedCandidates {
		if err := i.agent.AddRemoteCandidate(candidate); err != nil {
			return nil, fmt.Errorf("wire-connect: add remote ICE candidate: %w", err)
		}
	}
	if err := waitRemoteCandidates(ctx, i.agent, len(parsedCandidates)); err != nil {
		return nil, err
	}

	var (
		conn *pionice.Conn
		err  error
	)
	if i.host {
		conn, err = i.agent.Dial(ctx, remote.Ufrag, remote.Password)
	} else {
		conn, err = i.agent.Accept(ctx, remote.Ufrag, remote.Password)
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		i.mu.Lock()
		closed := i.closed
		i.mu.Unlock()
		if closed {
			return nil, ErrICEClosed
		}
		return nil, fmt.Errorf("wire-connect: ICE connect: %w", err)
	}
	monitored := &monitoredICEConn{Conn: conn, lost: i.lost, ctx: i.ctx, done: make(chan struct{})}
	go monitored.watch()
	return monitored, nil
}

// Close stops the Pion agent.  It is idempotent and safe to call from a
// context watcher while another goroutine is waiting in Connect or LocalOffer.
func (i *ICE) Close() error {
	if i == nil {
		return nil
	}
	i.closeOnce.Do(func() {
		i.mu.Lock()
		i.closed = true
		i.mu.Unlock()
		i.cancel()
		i.lostOnce.Do(func() { close(i.lost) })
		i.closeErr = i.agent.Close()
		close(i.closeDone)
	})
	<-i.closeDone
	return i.closeErr
}

// monitoredICEConn turns Pion's connection-state notifications into normal
// net.Conn closure semantics.  In particular, a consent timeout must unblock
// a goroutine already waiting in Read so Bind can retire this direct path and
// use DERP.
type monitoredICEConn struct {
	*pionice.Conn
	lost <-chan struct{}
	ctx  context.Context
	done chan struct{}
	once sync.Once
}

func (c *monitoredICEConn) watch() {
	select {
	case <-c.lost:
		_ = c.Conn.Close()
	case <-c.done:
	case <-c.ctx.Done():
		_ = c.Conn.Close()
	}
}

func (c *monitoredICEConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

func validateOffer(o Offer) error {
	if err := validateCredentials(o.Ufrag, o.Password); err != nil {
		return fmt.Errorf("wire-connect: invalid remote ICE credentials: %w", err)
	}
	if len(o.Candidates) == 0 {
		return errors.New("wire-connect: remote ICE offer has no candidates")
	}
	if len(o.Candidates) > maxOfferCandidates {
		return fmt.Errorf("wire-connect: remote ICE candidate count %d exceeds %d", len(o.Candidates), maxOfferCandidates)
	}
	totalCandidateBytes := 0
	for _, raw := range o.Candidates {
		if len(raw) == 0 || len(raw) > maxOfferCandidateLen || strings.IndexByte(raw, '\x00') >= 0 {
			return fmt.Errorf("wire-connect: invalid remote ICE candidate length")
		}
		totalCandidateBytes += len(raw)
		if totalCandidateBytes > maxOfferBytes {
			return fmt.Errorf("wire-connect: remote ICE offer exceeds %d bytes", maxOfferBytes)
		}
	}
	return nil
}

func normalizeExcludedIPs(raw []netip.Addr) (map[netip.Addr]struct{}, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	excluded := make(map[netip.Addr]struct{}, len(raw))
	for _, ip := range raw {
		if !ip.IsValid() {
			return nil, errors.New("wire-connect: excluded IP is invalid")
		}
		excluded[ip.Unmap()] = struct{}{}
	}
	return excluded, nil
}

func excludedIP(excluded map[netip.Addr]struct{}, ip net.IP) bool {
	if len(excluded) == 0 {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	_, ok = excluded[addr.Unmap()]
	return ok
}

func (i *ICE) isExcludedCandidate(candidate pionice.Candidate) bool {
	if i == nil || len(i.excludedIPs) == 0 || candidate == nil {
		return false
	}
	addr, err := netip.ParseAddr(candidate.Address())
	if err != nil {
		return false
	}
	_, ok := i.excludedIPs[addr.Unmap()]
	return ok
}

func validateCredentials(ufrag, password string) error {
	if ufrag == "" || password == "" {
		return errors.New("credentials must not be empty")
	}
	if len(ufrag) > maxOfferCredentialLen || len(password) > maxOfferCredentialLen {
		return fmt.Errorf("credentials exceed %d bytes", maxOfferCredentialLen)
	}
	if !utf8.ValidString(ufrag) || !utf8.ValidString(password) {
		return errors.New("credentials must be valid UTF-8")
	}
	for _, value := range []string{ufrag, password} {
		if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("credentials contain whitespace or control characters")
		}
	}
	return nil
}

func allowedCandidate(candidate pionice.Candidate) bool {
	if candidate == nil {
		return false
	}
	if _, err := netip.ParseAddr(candidate.Address()); err != nil {
		return false
	}
	if candidate.Component() != pionice.ComponentRTP {
		return false
	}
	if candidate.TCPType() != pionice.TCPTypeUnspecified {
		return false
	}
	switch candidate.NetworkType() {
	case pionice.NetworkTypeUDP4, pionice.NetworkTypeUDP6:
	default:
		return false
	}
	switch candidate.Type() {
	case pionice.CandidateTypeHost, pionice.CandidateTypeServerReflexive:
		return true
	default:
		return false
	}
}

func waitRemoteCandidates(ctx context.Context, agent *pionice.Agent, want int) error {
	if want == 0 {
		return nil
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		candidates, err := agent.GetRemoteCandidates()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("wire-connect: get remote ICE candidates: %w", err)
		}
		if len(candidates) >= want {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("wire-connect: remote ICE candidates were not applied")
		case <-ticker.C:
		}
	}
}
