// Package control implements the small, authenticated rendezvous service used
// by wire-connect clients.  It deliberately keeps the control plane separate
// from the relay and WireGuard data plane: the server only handles rendezvous
// messages and never sees the plaintext carried by a client tunnel.
package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
)

const (
	defaultRoomTTL    = 10 * time.Minute
	defaultMaxRooms   = 1024
	maxDevices        = 128
	maxRoomsPerDevice = 8
	maxPairs          = 1024
	maxPairsPerDevice = 32
	maxRelayKeys      = 4
	maxBodyBytes      = 64 << 10
	maxMessageBytes   = 32 << 10
	maxStateBytes     = 4 << 20
	messageQueueSize  = 32
	requestRateLimit  = 256

	// The ping interval is intentionally longer than the usual NAT idle
	// timeout.  A failed Ping is enough to tear down the connection; the
	// client can then reconnect through the control plane.
	websocketPingInterval = 20 * time.Second
	websocketPingTimeout  = 10 * time.Second
	websocketWriteTimeout = 10 * time.Second

	stateVersion = 1
)

var requestTimeout = 15 * time.Second

var (
	ErrStateDirRequired   = errors.New("control: state directory is required")
	ErrEnrollmentRequired = errors.New("control: enrollment token is required")
	ErrDeviceNotFound     = errors.New("control: device not found")
	ErrInvalidDeviceID    = errors.New("control: invalid device id")
	ErrServerClosed       = errors.New("control: server is closed")
	ErrStateInsecure      = errors.New("control: state path has insecure permissions or is a symlink")
	ErrEnrollmentMismatch = errors.New("control: enrollment token does not match state")
)

// Config controls a rendezvous Server.  EnrollmentToken is the server's
// enrollment credential and its SHA-256 digest is what is persisted.  It is
// required when creating a state directory; after that, an empty value is
// allowed so an operator can restart the service without putting the
// enrollment credential in a process configuration again.  StateDir must be a
// private directory owned by the service account.
type Config struct {
	StateDir        string
	EnrollmentToken string
	MaxRooms        int
	RoomTTL         time.Duration
	Log             *slog.Logger
}

// Message is the only application message accepted on a room or pair socket.
// Payload is intentionally opaque to the rendezvous service and is forwarded
// end-to-end between the two devices.
type Message struct {
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

// LoginRequest enrolls a new device with the server's enrollment credential.
type LoginRequest struct {
	Token string `json:"token"`
	Name  string `json:"name,omitempty"`
}

// LoginResponse contains a newly issued device credential.  The token is
// returned once and is never written to disk by this package.
type LoginResponse struct {
	Token    string `json:"token"`
	DeviceID string `json:"device_id"`
}

// CreateRoomRequest requests a four-character lower-case Crockford room ID.
// An empty ID asks the service to generate one.
type CreateRoomRequest struct {
	ID string `json:"id,omitempty"`
}

// CreateRoomResponse describes the short-lived room.
type CreateRoomResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CommitRequest binds a room to a long-lived pair identity.  Both room
// participants must submit the same 64-character hexadecimal ID.
type CommitRequest struct {
	PairID string `json:"pair_id"`
}

// CommitResponse reports whether both sides have submitted and the pair has
// been durably committed.
type CommitResponse struct {
	Committed bool `json:"committed"`
}

// Pair is the durable identity binding used after a short-code room expires.
type Pair struct {
	ID          string `json:"id"`
	HostDevice  string `json:"host_device"`
	GuestDevice string `json:"guest_device"`
}

// RelayRegisterRequest registers a DERP relay public key for the authenticated
// device.  The key is kept in memory only and expires after ten minutes.
type RelayRegisterRequest struct {
	Key string `json:"key"`
}

// RelayRegisterResponse reports the lease expiry.
type RelayRegisterResponse struct {
	ExpiresAt time.Time `json:"expires_at"`
}

type device struct {
	ID        string
	Name      string
	TokenHash string
	Revoked   bool
}

type room struct {
	ID          string
	HostDevice  string
	GuestDevice string
	CreatedAt   time.Time
	ExpiresAt   time.Time

	hostConn    *wsPeer
	guestConn   *wsPeer
	hostCommit  string
	guestCommit string
}

type pairState struct {
	Pair
	hostConn  *wsPeer
	guestConn *wsPeer
}

type relayLease struct {
	DeviceID string
	Expires  time.Time
}

// Server is an HTTP rendezvous service.  A Server is safe for concurrent use
// and should be closed when its HTTP listener is stopped.
type Server struct {
	cfg Config
	log *slog.Logger

	statePath            string
	stateLock            *stateLock
	enrollmentHash       [sha256.Size]byte
	enrollmentConfigured bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu          sync.Mutex
	closed      bool
	devices     map[string]*device
	byTokenHash map[string]string
	rooms       map[string]*room
	roomCounts  map[string]int
	pairs       map[string]*pairState
	relayKeys   map[string]relayLease

	ipLimiter         *rateLimiter
	credentialLimiter *rateLimiter
	peerWG            sync.WaitGroup
}

// New opens or creates the private state directory and loads durable device
// and pair state.  Short-lived rooms and relay leases intentionally do not
// survive a restart.
func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.StateDir) == "" {
		return nil, ErrStateDirRequired
	}
	if cfg.MaxRooms <= 0 {
		cfg.MaxRooms = defaultMaxRooms
	}
	if cfg.RoomTTL <= 0 {
		cfg.RoomTTL = defaultRoomTTL
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	stateDir, err := prepareStateDir(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	cfg.StateDir = stateDir
	lock, err := acquireStateLock(filepath.Join(stateDir, ".lock"))
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:                  cfg,
		log:                  cfg.Log,
		statePath:            filepath.Join(stateDir, "state.json"),
		stateLock:            lock,
		enrollmentConfigured: cfg.EnrollmentToken != "",
		devices:              make(map[string]*device),
		byTokenHash:          make(map[string]string),
		rooms:                make(map[string]*room),
		roomCounts:           make(map[string]int),
		pairs:                make(map[string]*pairState),
		relayKeys:            make(map[string]relayLease),
		ipLimiter:            newRateLimiter(4096, time.Minute, requestRateLimit),
		credentialLimiter:    newRateLimiter(4096, time.Minute, requestRateLimit),
	}
	if cfg.EnrollmentToken != "" {
		s.enrollmentHash = sha256.Sum256([]byte(cfg.EnrollmentToken))
	}

	exists, err := s.loadState()
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	if !exists {
		if cfg.EnrollmentToken == "" {
			_ = lock.Close()
			return nil, ErrEnrollmentRequired
		}
		s.mu.Lock()
		err = s.saveStateLocked()
		s.mu.Unlock()
		if err != nil {
			_ = lock.Close()
			return nil, err
		}
	}
	// The credential is needed only to derive/verify the digest during startup.
	// Keep no plaintext copy in a long-lived Server value.
	s.cfg.EnrollmentToken = ""

	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.cleanupLoop()
	return s, nil
}

// Handler returns the service's HTTP handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

// Close stops cleanup and closes all active WebSocket connections.  It is
// idempotent.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	peers := s.activePeersLocked()
	s.rooms = make(map[string]*room)
	s.roomCounts = make(map[string]int)
	s.relayKeys = make(map[string]relayLease)
	for _, p := range s.pairs {
		p.hostConn = nil
		p.guestConn = nil
	}
	s.mu.Unlock()

	for _, peer := range peers {
		peer.stop()
	}
	s.peerWG.Wait()
	s.wg.Wait()
	return s.stateLock.Close()
}

// RevokeDevice permanently disables a device token and all of its relay
// leases.  Existing sockets are closed promptly; durable pair records are
// retained so an administrator can audit or re-enroll the device later.
func (s *Server) RevokeDevice(id string) error {
	canonicalID, ok := normalizeHex(id, 32)
	if !ok {
		return ErrInvalidDeviceID
	}
	id = canonicalID

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrServerClosed
	}
	d, ok := s.devices[id]
	if !ok {
		s.mu.Unlock()
		return ErrDeviceNotFound
	}
	if d.Revoked {
		s.mu.Unlock()
		return nil
	}
	d.Revoked = true
	removedLeases := make(map[string]relayLease)
	for key, lease := range s.relayKeys {
		if lease.DeviceID == id {
			removedLeases[key] = lease
			delete(s.relayKeys, key)
		}
	}
	if err := s.saveStateLocked(); err != nil {
		d.Revoked = false
		for key, lease := range removedLeases {
			s.relayKeys[key] = lease
		}
		s.mu.Unlock()
		return err
	}
	// Remove rooms first.  This also returns their peers; collecting the
	// remaining device peers afterwards keeps a room socket from appearing in
	// both lists.  stop is idempotent, but avoiding duplicate entries keeps
	// shutdown and callback accounting straightforward.
	peers := s.removeRoomsForDeviceLocked(id)
	peers = append(peers, s.peersForDeviceLocked(id)...)
	s.mu.Unlock()
	for _, peer := range peers {
		peer.stop()
	}
	return nil
}

// AllowedRelayKey checks that a currently leased relay key belongs to a
// non-revoked device.  The key is accepted in either hex case, but malformed
// keys are rejected without touching the lease table.
func (s *Server) AllowedRelayKey(key string) bool {
	key, ok := normalizeHex(key, 64)
	if !ok {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	lease, ok := s.relayKeys[key]
	if ok {
		d := s.devices[lease.DeviceID]
		if d == nil || d.Revoked || !now.Before(lease.Expires) {
			delete(s.relayKeys, key)
			ok = false
		}
	}
	s.mu.Unlock()
	return ok
}

func (s *Server) cleanupLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanupExpired()
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Server) cleanupExpired() {
	now := time.Now()
	var peers []*wsPeer
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	for id, r := range s.rooms {
		if now.Before(r.ExpiresAt) {
			continue
		}
		if r.hostConn != nil {
			peers = append(peers, r.hostConn)
		}
		if r.guestConn != nil {
			peers = append(peers, r.guestConn)
		}
		s.decrementRoomCountLocked(r.HostDevice)
		delete(s.rooms, id)
	}
	for key, lease := range s.relayKeys {
		if !now.Before(lease.Expires) {
			delete(s.relayKeys, key)
		}
	}
	s.mu.Unlock()
	for _, peer := range peers {
		peer.stop()
	}
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)

	var d *device
	if r.URL.Path != "/v1/login" {
		var ok, limited bool
		d, ok, limited = s.authenticate(r)
		if !ok {
			if limited {
				writeRateLimit(w)
				return
			}
			writeAuthError(w)
			return
		}
	}

	switch {
	case r.URL.Path == "/v1/login":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		s.handleLogin(w, r)
	case r.URL.Path == "/v1/rooms":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		s.handleCreateRoom(w, r, d)
	case strings.HasPrefix(r.URL.Path, "/v1/rooms/"):
		s.handleRoomRoute(w, r, d)
	case strings.HasPrefix(r.URL.Path, "/v1/pairs/"):
		s.handlePairRoute(w, r, d)
	case r.URL.Path == "/v1/relay/register":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		s.handleRelayRegister(w, r, d)
	default:
		writeError(w, http.StatusNotFound, "not_found")
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.ipLimiter.allow(clientIP(r)) {
		writeRateLimit(w)
		return
	}
	var req LoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Token == "" || len(req.Token) > 4096 {
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	h := hashString(req.Token)
	hashText := hex.EncodeToString(h[:])
	if !s.credentialLimiter.allow("login:" + hashText) {
		writeRateLimit(w)
		return
	}
	if !secureEqual(h[:], s.enrollmentHash[:]) {
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	name := strings.TrimSpace(req.Name)
	if len(name) > 128 || !utf8.ValidString(name) {
		writeError(w, http.StatusBadRequest, "invalid_name")
		return
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "closed")
		return
	}
	if len(s.devices) >= maxDevices {
		s.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "device_limit")
		return
	}
	token, err := randomToken()
	if err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	deviceID, err := randomDeviceID()
	if err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	for {
		if _, exists := s.devices[deviceID]; !exists {
			break
		}
		deviceID, err = randomDeviceID()
		if err != nil {
			s.mu.Unlock()
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}
	}
	tokenHash := hashString(token)
	tokenHashText := hex.EncodeToString(tokenHash[:])
	for {
		if _, exists := s.byTokenHash[tokenHashText]; !exists {
			break
		}
		token, err = randomToken()
		if err != nil {
			s.mu.Unlock()
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		tokenHash = hashString(token)
		tokenHashText = hex.EncodeToString(tokenHash[:])
	}
	s.devices[deviceID] = &device{ID: deviceID, Name: name, TokenHash: tokenHashText}
	s.byTokenHash[tokenHashText] = deviceID
	if err := s.saveStateLocked(); err != nil {
		delete(s.devices, deviceID)
		delete(s.byTokenHash, tokenHashText)
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusCreated, LoginResponse{Token: token, DeviceID: deviceID})
}

func (s *Server) handleCreateRoom(w http.ResponseWriter, r *http.Request, d *device) {
	var req CreateRoomRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	id := strings.TrimSpace(req.ID)
	if id != "" && !validRoomID(id) {
		writeError(w, http.StatusBadRequest, "invalid_room_id")
		return
	}

	now := time.Now()
	s.mu.Lock()
	if s.closed || d.Revoked {
		s.mu.Unlock()
		if s.closed {
			writeError(w, http.StatusServiceUnavailable, "closed")
		} else {
			writeAuthError(w)
		}
		return
	}
	expiredPeers := s.removeExpiredRoomsLocked(now)
	stopExpired := func() {
		for _, peer := range expiredPeers {
			peer.stop()
		}
	}
	if len(s.rooms) >= s.cfg.MaxRooms {
		s.mu.Unlock()
		stopExpired()
		writeError(w, http.StatusTooManyRequests, "room_limit")
		return
	}
	if s.roomCounts[d.ID] >= maxRoomsPerDevice {
		s.mu.Unlock()
		stopExpired()
		writeError(w, http.StatusTooManyRequests, "device_room_limit")
		return
	}
	var err error
	if id == "" {
		for attempt := 0; attempt < 32; attempt++ {
			id, err = randomRoomID()
			if err != nil {
				s.mu.Unlock()
				stopExpired()
				writeError(w, http.StatusInternalServerError, "internal_error")
				return
			}
			if _, exists := s.rooms[id]; !exists {
				break
			}
			id = ""
		}
		if id == "" {
			s.mu.Unlock()
			stopExpired()
			writeError(w, http.StatusConflict, "room_id_unavailable")
			return
		}
	}
	if _, exists := s.rooms[id]; exists {
		s.mu.Unlock()
		stopExpired()
		writeError(w, http.StatusConflict, "room_exists")
		return
	}
	rm := &room{
		ID:         id,
		HostDevice: d.ID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.cfg.RoomTTL),
	}
	s.rooms[id] = rm
	s.roomCounts[d.ID]++
	s.mu.Unlock()
	stopExpired()

	writeJSON(w, http.StatusCreated, CreateRoomResponse{ID: id, ExpiresAt: rm.ExpiresAt})
}

func (s *Server) handleRoomRoute(w http.ResponseWriter, r *http.Request, d *device) {
	parts := splitPath(r.URL.Path)
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != "rooms" || !validRoomID(parts[2]) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	id := parts[2]
	switch {
	case parts[3] == "socket":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		s.handleRoomSocket(w, r, d, id)
	case parts[3] == "commit":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		s.handleCommit(w, r, d, id)
	default:
		writeError(w, http.StatusNotFound, "not_found")
	}
}

func (s *Server) handlePairRoute(w http.ResponseWriter, r *http.Request, d *device) {
	parts := splitPath(r.URL.Path)
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != "pairs" || !validPairID(parts[2]) || parts[3] != "socket" {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	s.handlePairSocket(w, r, d, strings.ToLower(parts[2]))
}

func (s *Server) handleRelayRegister(w http.ResponseWriter, r *http.Request, d *device) {
	var req RelayRegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	key, ok := normalizeHex(req.Key, 64)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_relay_key")
		return
	}
	now := time.Now()
	s.mu.Lock()
	if s.closed || d.Revoked {
		s.mu.Unlock()
		if s.closed {
			writeError(w, http.StatusServiceUnavailable, "closed")
		} else {
			writeAuthError(w)
		}
		return
	}
	s.expireRelayLocked(now)
	if existing, exists := s.relayKeys[key]; exists && existing.DeviceID != d.ID {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "relay_key_in_use")
		return
	}
	count := 0
	for _, lease := range s.relayKeys {
		if lease.DeviceID == d.ID {
			count++
		}
	}
	if _, exists := s.relayKeys[key]; !exists && count >= maxRelayKeys {
		s.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "relay_key_limit")
		return
	}
	expires := now.Add(10 * time.Minute)
	s.relayKeys[key] = relayLease{DeviceID: d.ID, Expires: expires}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, RelayRegisterResponse{ExpiresAt: expires})
}

func (s *Server) handleCommit(w http.ResponseWriter, r *http.Request, d *device, roomID string) {
	var req CommitRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	pairID, ok := normalizeHex(req.PairID, 64)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_pair_id")
		return
	}

	s.mu.Lock()
	if s.closed || d.Revoked {
		s.mu.Unlock()
		if s.closed {
			writeError(w, http.StatusServiceUnavailable, "closed")
		} else {
			writeAuthError(w)
		}
		return
	}
	rm, exists := s.rooms[roomID]
	if !exists || !time.Now().Before(rm.ExpiresAt) {
		// A successful commit is durable even if the response was lost or
		// the short-lived room disappeared during a restart.  Let either
		// member safely retry the same commit by its pair ID.
		if committedPair := s.pairs[pairID]; committedPair != nil &&
			(d.ID == committedPair.HostDevice || d.ID == committedPair.GuestDevice) {
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, CommitResponse{Committed: true})
			return
		}
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "room_not_found")
		return
	}
	role := ""
	switch {
	case d.ID == rm.HostDevice:
		role = "host"
	case rm.GuestDevice != "" && d.ID == rm.GuestDevice:
		role = "guest"
	default:
		s.mu.Unlock()
		writeError(w, http.StatusForbidden, "room_forbidden")
		return
	}
	if rm.pairID() != "" && rm.pairID() != pairID {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "room_committed")
		return
	}
	if existing := s.pairs[pairID]; existing != nil &&
		(existing.HostDevice != rm.HostDevice || existing.GuestDevice != rm.GuestDevice) {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "pair_id_in_use")
		return
	}
	oldHost, oldGuest := rm.hostCommit, rm.guestCommit
	if role == "host" {
		if rm.hostCommit != "" && rm.hostCommit != pairID {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, "commit_mismatch")
			return
		}
		rm.hostCommit = pairID
	} else {
		if rm.guestCommit != "" && rm.guestCommit != pairID {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, "commit_mismatch")
			return
		}
		rm.guestCommit = pairID
	}
	committed := rm.hostCommit != "" && rm.guestCommit != "" && rm.GuestDevice != "" && rm.hostCommit == rm.guestCommit
	createdPair := false
	if committed {
		if _, exists := s.pairs[pairID]; !exists {
			if len(s.pairs) >= maxPairs {
				rm.hostCommit, rm.guestCommit = oldHost, oldGuest
				s.mu.Unlock()
				writeError(w, http.StatusTooManyRequests, "pair_limit")
				return
			}
			if s.pairDeviceCountLocked(rm.HostDevice) >= maxPairsPerDevice || s.pairDeviceCountLocked(rm.GuestDevice) >= maxPairsPerDevice {
				rm.hostCommit, rm.guestCommit = oldHost, oldGuest
				s.mu.Unlock()
				writeError(w, http.StatusTooManyRequests, "device_pair_limit")
				return
			}
			s.pairs[pairID] = &pairState{Pair: Pair{ID: pairID, HostDevice: rm.HostDevice, GuestDevice: rm.GuestDevice}}
			createdPair = true
		}
		if err := s.saveStateLocked(); err != nil {
			rm.hostCommit, rm.guestCommit = oldHost, oldGuest
			if createdPair {
				delete(s.pairs, pairID)
			}
			s.mu.Unlock()
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, CommitResponse{Committed: committed})
}

func (s *Server) handleRoomSocket(w http.ResponseWriter, r *http.Request, d *device, id string) {
	role := r.URL.Query().Get("role")
	if role != "host" && role != "guest" {
		writeError(w, http.StatusBadRequest, "invalid_role")
		return
	}

	// Check authorization before upgrading.  A second concurrent handshake is
	// rechecked below after the upgrade so it cannot steal a slot in a race.
	s.mu.Lock()
	if s.closed || d.Revoked {
		s.mu.Unlock()
		if s.closed {
			writeError(w, http.StatusServiceUnavailable, "closed")
		} else {
			writeAuthError(w)
		}
		return
	}
	rm, exists := s.rooms[id]
	if !exists || !time.Now().Before(rm.ExpiresAt) {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "room_not_found")
		return
	}
	if err := validateRoomSlot(rm, d.ID, role); err != nil {
		s.mu.Unlock()
		writeSlotError(w, err)
		return
	}
	s.mu.Unlock()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		return
	}
	peer := newWSPeer(conn)

	s.mu.Lock()
	rm, exists = s.rooms[id]
	if s.closed || d.Revoked || !exists || !time.Now().Before(rm.ExpiresAt) || validateRoomSlot(rm, d.ID, role) != nil {
		s.mu.Unlock()
		peer.stop()
		return
	}
	if role == "host" {
		rm.hostConn = peer
	} else {
		if rm.GuestDevice == "" {
			rm.GuestDevice = d.ID
		}
		rm.guestConn = peer
	}
	other := roomOtherConn(rm, role)
	both := roomBothConnected(rm)
	s.peerWG.Add(1)
	s.mu.Unlock()

	if both {
		// Queue the readiness event before starting the reader.  This gives the
		// newly connected client a strict first-message barrier, so a client
		// that immediately sends PAKE data cannot overtake peer=true.
		msg := peerEvent(true)
		peer.enqueue(msg)
		if other != nil {
			other.enqueue(msg)
		}
	}
	s.startPeer(peer,
		func(data []byte) { s.forwardRoomMessage(id, role, peer, data) },
		func() { s.detachRoom(id, role, peer) },
	)
}

func (s *Server) handlePairSocket(w http.ResponseWriter, r *http.Request, d *device, id string) {
	s.mu.Lock()
	if s.closed || d.Revoked {
		s.mu.Unlock()
		if s.closed {
			writeError(w, http.StatusServiceUnavailable, "closed")
		} else {
			writeAuthError(w)
		}
		return
	}
	ps, exists := s.pairs[id]
	if !exists {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "pair_not_found")
		return
	}
	role := ""
	switch {
	case d.ID == ps.HostDevice:
		role = "host"
	case d.ID == ps.GuestDevice:
		role = "guest"
	default:
		s.mu.Unlock()
		writeError(w, http.StatusForbidden, "pair_forbidden")
		return
	}
	if pairConn(ps, role) != nil {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "socket_in_use")
		return
	}
	s.mu.Unlock()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		return
	}
	peer := newWSPeer(conn)

	s.mu.Lock()
	ps, exists = s.pairs[id]
	if s.closed || d.Revoked || !exists || pairConn(ps, role) != nil {
		s.mu.Unlock()
		peer.stop()
		return
	}
	if role == "host" {
		ps.hostConn = peer
	} else {
		ps.guestConn = peer
	}
	other := pairOtherConn(ps, role)
	both := pairBothConnected(ps)
	s.peerWG.Add(1)
	s.mu.Unlock()

	if both {
		msg := peerEvent(true)
		peer.enqueue(msg)
		if other != nil {
			other.enqueue(msg)
		}
	}
	s.startPeer(peer,
		func(data []byte) { s.forwardPairMessage(id, role, peer, data) },
		func() { s.detachPair(id, role, peer) },
	)
}

func (s *Server) startPeer(peer *wsPeer, onMessage func([]byte), onClose func()) {
	peer.start(s.ctx, onMessage, func() {
		onClose()
		s.peerWG.Done()
	})
}

func validateRoomSlot(rm *room, deviceID, role string) error {
	if role == "host" {
		if rm.HostDevice != deviceID {
			return errSlotForbidden
		}
		if rm.hostConn != nil && !rm.hostConn.stopped() {
			return errSlotInUse
		}
		return nil
	}
	if rm.HostDevice == deviceID {
		return errSlotForbidden
	}
	if rm.GuestDevice != "" && rm.GuestDevice != deviceID {
		return errSlotForbidden
	}
	if rm.guestConn != nil && !rm.guestConn.stopped() {
		return errSlotInUse
	}
	return nil
}

var (
	errSlotForbidden = errors.New("forbidden")
	errSlotInUse     = errors.New("in_use")
)

func writeSlotError(w http.ResponseWriter, err error) {
	if errors.Is(err, errSlotInUse) {
		writeError(w, http.StatusConflict, "socket_in_use")
		return
	}
	writeError(w, http.StatusForbidden, "room_forbidden")
}

func (s *Server) forwardRoomMessage(id, role string, source *wsPeer, data []byte) {
	if !validClientMessage(data) {
		source.stop()
		return
	}
	s.mu.Lock()
	rm := s.rooms[id]
	if rm == nil || (role == "host" && rm.hostConn != source) || (role == "guest" && rm.guestConn != source) {
		s.mu.Unlock()
		return
	}
	other := roomOtherConn(rm, role)
	both := roomBothConnected(rm)
	s.mu.Unlock()
	if both && other != nil {
		other.enqueue(data)
	}
}

func (s *Server) forwardPairMessage(id, role string, source *wsPeer, data []byte) {
	if !validClientMessage(data) {
		source.stop()
		return
	}
	s.mu.Lock()
	ps := s.pairs[id]
	if ps == nil || (role == "host" && ps.hostConn != source) || (role == "guest" && ps.guestConn != source) {
		s.mu.Unlock()
		return
	}
	other := pairOtherConn(ps, role)
	both := pairBothConnected(ps)
	s.mu.Unlock()
	if both && other != nil {
		other.enqueue(data)
	}
}

func (s *Server) detachRoom(id, role string, source *wsPeer) {
	var other *wsPeer
	s.mu.Lock()
	rm := s.rooms[id]
	if rm == nil {
		s.mu.Unlock()
		return
	}
	// The source may have marked itself stopped before the callback runs. It
	// still occupied a slot, so the remaining peer must receive connected=false.
	both := rm.hostConn != nil && rm.guestConn != nil
	if role == "host" {
		if rm.hostConn != source {
			s.mu.Unlock()
			return
		}
		rm.hostConn = nil
		other = rm.guestConn
	} else {
		if rm.guestConn != source {
			s.mu.Unlock()
			return
		}
		rm.guestConn = nil
		other = rm.hostConn
	}
	s.mu.Unlock()
	if both && other != nil {
		other.enqueue(peerEvent(false))
	}
}

func (s *Server) detachPair(id, role string, source *wsPeer) {
	var other *wsPeer
	s.mu.Lock()
	ps := s.pairs[id]
	if ps == nil {
		s.mu.Unlock()
		return
	}
	// The source may have marked itself stopped before the callback runs. It
	// still occupied a slot, so the remaining peer must receive connected=false.
	both := ps.hostConn != nil && ps.guestConn != nil
	if role == "host" {
		if ps.hostConn != source {
			s.mu.Unlock()
			return
		}
		ps.hostConn = nil
		other = ps.guestConn
	} else {
		if ps.guestConn != source {
			s.mu.Unlock()
			return
		}
		ps.guestConn = nil
		other = ps.hostConn
	}
	s.mu.Unlock()
	if both && other != nil {
		other.enqueue(peerEvent(false))
	}
}

func roomOtherConn(rm *room, role string) *wsPeer {
	if role == "host" {
		if rm.guestConn != nil && !rm.guestConn.stopped() {
			return rm.guestConn
		}
		return nil
	}
	if rm.hostConn != nil && !rm.hostConn.stopped() {
		return rm.hostConn
	}
	return nil
}

func pairConn(ps *pairState, role string) *wsPeer {
	if role == "host" {
		if ps.hostConn != nil && !ps.hostConn.stopped() {
			return ps.hostConn
		}
		return nil
	}
	if ps.guestConn != nil && !ps.guestConn.stopped() {
		return ps.guestConn
	}
	return nil
}

func pairOtherConn(ps *pairState, role string) *wsPeer {
	if role == "host" {
		if ps.guestConn != nil && !ps.guestConn.stopped() {
			return ps.guestConn
		}
		return nil
	}
	if ps.hostConn != nil && !ps.hostConn.stopped() {
		return ps.hostConn
	}
	return nil
}

func roomBothConnected(rm *room) bool {
	return rm != nil && rm.hostConn != nil && !rm.hostConn.stopped() && rm.guestConn != nil && !rm.guestConn.stopped()
}

func pairBothConnected(ps *pairState) bool {
	return ps != nil && ps.hostConn != nil && !ps.hostConn.stopped() && ps.guestConn != nil && !ps.guestConn.stopped()
}

// The pair ID is kept on a room as a short-lived implementation detail.  It
// is deliberately derived rather than exposed as a room field.
func (r *room) pairID() string {
	if r.hostCommit != "" && r.hostCommit == r.guestCommit && r.GuestDevice != "" {
		return r.hostCommit
	}
	return ""
}

func (s *Server) activePeersLocked() []*wsPeer {
	seen := make(map[*wsPeer]struct{})
	var peers []*wsPeer
	for _, rm := range s.rooms {
		for _, p := range []*wsPeer{rm.hostConn, rm.guestConn} {
			if p != nil {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					peers = append(peers, p)
				}
			}
		}
	}
	for _, ps := range s.pairs {
		for _, p := range []*wsPeer{ps.hostConn, ps.guestConn} {
			if p != nil {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					peers = append(peers, p)
				}
			}
		}
	}
	return peers
}

func (s *Server) peersForDeviceLocked(id string) []*wsPeer {
	seen := make(map[*wsPeer]struct{})
	var peers []*wsPeer
	for _, rm := range s.rooms {
		if rm.HostDevice == id && rm.hostConn != nil {
			seen[rm.hostConn] = struct{}{}
		}
		if rm.GuestDevice == id && rm.guestConn != nil {
			seen[rm.guestConn] = struct{}{}
		}
	}
	for _, ps := range s.pairs {
		if ps.HostDevice == id && ps.hostConn != nil {
			seen[ps.hostConn] = struct{}{}
		}
		if ps.GuestDevice == id && ps.guestConn != nil {
			seen[ps.guestConn] = struct{}{}
		}
	}
	peers = make([]*wsPeer, 0, len(seen))
	for p := range seen {
		peers = append(peers, p)
	}
	return peers
}

func (s *Server) removeExpiredRoomsLocked(now time.Time) []*wsPeer {
	var peers []*wsPeer
	for id, rm := range s.rooms {
		if !now.Before(rm.ExpiresAt) {
			if rm.hostConn != nil {
				peers = append(peers, rm.hostConn)
			}
			if rm.guestConn != nil {
				peers = append(peers, rm.guestConn)
			}
			s.decrementRoomCountLocked(rm.HostDevice)
			delete(s.rooms, id)
		}
	}
	return peers
}

func (s *Server) removeRoomsForDeviceLocked(deviceID string) []*wsPeer {
	var peers []*wsPeer
	for id, rm := range s.rooms {
		if rm.HostDevice != deviceID && rm.GuestDevice != deviceID {
			continue
		}
		if rm.hostConn != nil {
			peers = append(peers, rm.hostConn)
		}
		if rm.guestConn != nil {
			peers = append(peers, rm.guestConn)
		}
		s.decrementRoomCountLocked(rm.HostDevice)
		delete(s.rooms, id)
	}
	return peers
}

func (s *Server) decrementRoomCountLocked(deviceID string) {
	if count := s.roomCounts[deviceID]; count <= 1 {
		delete(s.roomCounts, deviceID)
	} else {
		s.roomCounts[deviceID] = count - 1
	}
}

func (s *Server) expireRelayLocked(now time.Time) {
	for key, lease := range s.relayKeys {
		if !now.Before(lease.Expires) {
			delete(s.relayKeys, key)
		}
	}
}

func (s *Server) pairDeviceCountLocked(deviceID string) int {
	count := 0
	for _, pair := range s.pairs {
		if pair.HostDevice == deviceID || pair.GuestDevice == deviceID {
			count++
		}
	}
	return count
}

func splitPath(path string) []string {
	return strings.Split(strings.Trim(path, "/"), "/")
}

func writeAuthError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="wire-connect"`)
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

func writeRateLimit(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeError(w, http.StatusTooManyRequests, "rate_limited")
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid_json")
		} else if strings.Contains(err.Error(), "request body too large") {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_json")
		}
		return false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil && strings.Contains(err.Error(), "request body too large") {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_json")
		}
		return false
	}
	return true
}

func (s *Server) authenticate(r *http.Request) (*device, bool, bool) {
	if !s.ipLimiter.allow(clientIP(r)) {
		return nil, false, true
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return nil, false, false
	}
	token := strings.TrimSpace(auth[len(prefix):])
	if token == "" || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n") {
		return nil, false, false
	}
	h := hashString(token)
	hashText := hex.EncodeToString(h[:])
	if !s.credentialLimiter.allow("auth:" + hashText) {
		return nil, false, true
	}
	s.mu.Lock()
	id, ok := s.byTokenHash[hashText]
	d := s.devices[id]
	if !ok || d == nil || d.Revoked {
		s.mu.Unlock()
		return nil, false, false
	}
	s.mu.Unlock()
	return d, true, false
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func hashString(value string) [sha256.Size]byte {
	return sha256.Sum256([]byte(value))
}

func secureEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomDeviceID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

const crockfordLower = "0123456789abcdefghjkmnpqrstvwxyz"

func randomRoomID() (string, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = crockfordLower[int(b[i])&31]
	}
	return string(b), nil
}

func validRoomID(id string) bool {
	if len(id) != 4 {
		return false
	}
	for i := range id {
		if !strings.ContainsRune(crockfordLower, rune(id[i])) {
			return false
		}
	}
	return true
}

func validPairID(id string) bool {
	_, ok := normalizeHex(id, 64)
	return ok
}

func validDeviceID(id string) bool {
	_, ok := normalizeHex(id, 32)
	return ok
}

func normalizeHex(value string, length int) (string, bool) {
	if len(value) != length {
		return "", false
	}
	value = strings.ToLower(value)
	b, err := hex.DecodeString(value)
	if err != nil || len(b)*2 != length {
		return "", false
	}
	return value, true
}

// rateLimiter is a bounded fixed-window limiter.  It deliberately stores only
// hashes/pseudonyms supplied by callers; it is not a source of credential
// material and is periodically compacted as keys are reused.
type rateLimiter struct {
	mu       sync.Mutex
	entries  map[string]rateEntry
	max      int
	interval time.Duration
	limit    int
}

type rateEntry struct {
	start time.Time
	count int
}

func newRateLimiter(max int, interval time.Duration, limit int) *rateLimiter {
	return &rateLimiter{entries: make(map[string]rateEntry), max: max, interval: interval, limit: limit}
}

func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	if !ok || now.Sub(entry.start) >= l.interval {
		if !ok && len(l.entries) >= l.max {
			// The map is intentionally bounded.  Evict the oldest entry; no
			// security decision depends on which idle bucket is discarded.
			var oldestKey string
			var oldest time.Time
			for k, e := range l.entries {
				if oldestKey == "" || e.start.Before(oldest) {
					oldestKey, oldest = k, e.start
				}
			}
			delete(l.entries, oldestKey)
		}
		l.entries[key] = rateEntry{start: now, count: 1}
		return true
	}
	if entry.count >= l.limit {
		return false
	}
	entry.count++
	l.entries[key] = entry
	return true
}
