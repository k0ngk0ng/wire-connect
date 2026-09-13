package secure

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	sessionVersion         = 1
	sessionHelloHeaderLen  = 4 + 1 + 1 + chacha20poly1305.NonceSizeX
	sessionHelloPlainLen   = 1 + 32
	sessionHelloFrameLen   = sessionHelloHeaderLen + sessionHelloPlainLen + chacha20poly1305.Overhead
	sessionFrameHeaderLen  = 4 + 1 + 1 + 8
	sessionMaxPayload      = 64 << 10
	sessionMaxFrame        = sessionFrameHeaderLen + sessionMaxPayload + chacha20poly1305.Overhead
	sessionChallengeLength = 32
	sessionNoncePrefixLen  = 16
	sessionReplayWindow    = 64
	maxSessionContextLen   = maxPairContextLen
)

const (
	sessionRoleHost  byte = 0
	sessionRoleGuest byte = 1
)

var sessionMagic = [4]byte{'W', 'C', 'S', '1'}

var (
	errSessionClosed       = errors.New("wire-connect: session is closed")
	errSessionNotReady     = errors.New("wire-connect: session handshake is not complete")
	errSessionHelloState   = errors.New("wire-connect: invalid session hello state")
	errSessionInvalidHello = errors.New("wire-connect: invalid session hello")
	errSessionInvalidFrame = errors.New("wire-connect: invalid session frame")
	errSessionReplay       = errors.New("wire-connect: replayed or expired session frame")
	errSessionSequence     = errors.New("wire-connect: session sequence exhausted")
)

// Session protects the post-pairing control exchange. Hello authenticates two
// fresh random challenges with a key derived from the PAKE root. Once both
// challenges are accepted, Seal and Open use role-separated traffic keys and
// an authenticated monotonically increasing sequence number.
type Session struct {
	mu sync.Mutex

	role          byte
	contextDigest [sha256.Size]byte
	baseKey       []byte
	helloKey      []byte

	hello       []byte
	challenge   [sessionChallengeLength]byte
	haveHello   bool
	peer        [sessionChallengeLength]byte
	havePeer    bool
	ready       bool
	closed      bool
	txKey       []byte
	rxKey       []byte
	txNonceBase [sessionNoncePrefixLen]byte
	rxNonceBase [sessionNoncePrefixLen]byte

	nextSend uint64
	highest  uint64
	recvBits uint64
	haveRecv bool
}

// NewSession creates a session from the 32-byte root returned by Pair. The
// root is copied only through key derivation and is not retained. Context must
// be identical on both peers; a mismatch makes Hello authentication fail.
func NewSession(secret []byte, host bool, contextValue string) (*Session, error) {
	if len(secret) != pairRootLength {
		return nil, errors.New("wire-connect: session root secret must be 32 bytes")
	}
	if len(contextValue) == 0 || len(contextValue) > maxSessionContextLen {
		return nil, errors.New("wire-connect: invalid session context")
	}

	role := sessionRoleGuest
	if host {
		role = sessionRoleHost
	}
	contextDigest := sessionContextDigest(contextValue)
	baseInfo := sessionKDFInfo("wire-connect/session-base/v1", contextDigest[:])
	baseKey, err := deriveHKDF(secret, nil, baseInfo, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	helloInfo := sessionKDFInfo("wire-connect/session-hello/v1", contextDigest[:])
	helloKey, err := deriveHKDF(secret, nil, helloInfo, chacha20poly1305.KeySize)
	if err != nil {
		zeroBytes(baseKey)
		return nil, err
	}

	return &Session{
		role:          role,
		contextDigest: contextDigest,
		baseKey:       baseKey,
		helloKey:      helloKey,
	}, nil
}

// Hello creates (or returns a copy of) this side's authenticated challenge.
// The result is safe to retransmit over a reliable exchange; it is bound to
// this Session and cannot be reused by a different root or context.
func (s *Session) Hello() ([]byte, error) {
	if s == nil {
		return nil, errSessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errSessionClosed
	}
	if s.haveHello {
		return append([]byte(nil), s.hello...), nil
	}

	if _, err := io.ReadFull(rand.Reader, s.challenge[:]); err != nil {
		return nil, fmt.Errorf("wire-connect: generate session challenge: %w", err)
	}
	if isAllZero(s.challenge[:]) {
		return nil, errors.New("wire-connect: generated an invalid session challenge")
	}
	var nonce [chacha20poly1305.NonceSizeX]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		zeroBytes(s.challenge[:])
		return nil, fmt.Errorf("wire-connect: generate session nonce: %w", err)
	}
	aead, err := chacha20poly1305.NewX(s.helloKey)
	if err != nil {
		zeroBytes(s.challenge[:])
		return nil, fmt.Errorf("wire-connect: initialize session hello: %w", err)
	}
	header := make([]byte, sessionHelloHeaderLen)
	copy(header[:4], sessionMagic[:])
	header[4] = sessionVersion
	header[5] = s.role
	copy(header[6:], nonce[:])
	aad := sessionAAD(header, s.contextDigest[:])
	plaintext := make([]byte, sessionHelloPlainLen)
	plaintext[0] = s.role
	copy(plaintext[1:], s.challenge[:])
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	zeroBytes(plaintext)
	zeroBytes(aad)
	frame := make([]byte, 0, len(header)+len(ciphertext))
	frame = append(frame, header...)
	frame = append(frame, ciphertext...)
	zeroBytes(header)
	zeroBytes(ciphertext)
	s.hello = frame
	s.haveHello = true
	return append([]byte(nil), frame...), nil
}

// AcceptHello authenticates the peer's challenge and derives both direction
// keys. Hello must have been called first so the local side contributes a
// fresh challenge to the key schedule.
func (s *Session) AcceptHello(peerHello []byte) error {
	if s == nil {
		return errSessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSessionClosed
	}
	if !s.haveHello || s.ready || s.havePeer {
		return errSessionHelloState
	}
	if len(peerHello) != sessionHelloFrameLen {
		return errSessionInvalidHello
	}
	if subtle.ConstantTimeCompare(peerHello[:4], sessionMagic[:]) != 1 ||
		peerHello[4] != sessionVersion || peerHello[5] == s.role ||
		(peerHello[5] != sessionRoleHost && peerHello[5] != sessionRoleGuest) {
		return errSessionInvalidHello
	}
	aead, err := chacha20poly1305.NewX(s.helloKey)
	if err != nil {
		return errSessionInvalidHello
	}
	nonce := peerHello[6:sessionHelloHeaderLen]
	aad := sessionAAD(peerHello[:sessionHelloHeaderLen], s.contextDigest[:])
	plaintext, err := aead.Open(nil, nonce, peerHello[sessionHelloHeaderLen:], aad)
	zeroBytes(aad)
	if err != nil || len(plaintext) != sessionHelloPlainLen || plaintext[0] != peerHello[5] ||
		isAllZero(plaintext[1:]) || subtle.ConstantTimeCompare(plaintext[1:], s.challenge[:]) == 1 {
		zeroBytes(plaintext)
		return errSessionInvalidHello
	}
	copy(s.peer[:], plaintext[1:])
	zeroBytes(plaintext)
	if err := s.deriveTrafficLocked(); err != nil {
		zeroBytes(s.peer[:])
		return err
	}
	s.havePeer = true
	s.ready = true
	return nil
}

// Seal encrypts one control message. Messages larger than 64 KiB are
// rejected before allocation. Sequence numbers and direction are included in
// the authenticated data.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	if s == nil {
		return nil, errSessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errSessionClosed
	}
	if !s.ready {
		return nil, errSessionNotReady
	}
	if len(plaintext) > sessionMaxPayload {
		return nil, errors.New("wire-connect: session payload exceeds size limit")
	}
	if s.nextSend == ^uint64(0) {
		return nil, errSessionSequence
	}
	seq := s.nextSend
	header := make([]byte, sessionFrameHeaderLen)
	copy(header[:4], sessionMagic[:])
	header[4] = sessionVersion
	header[5] = s.txRole()
	binary.BigEndian.PutUint64(header[6:], seq)
	aad := sessionAAD(header, s.contextDigest[:])
	nonce := sessionNonce(s.txNonceBase, seq)
	aead, err := chacha20poly1305.NewX(s.txKey)
	if err != nil {
		zeroBytes(header)
		zeroBytes(aad)
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	zeroBytes(aad)
	frame := make([]byte, 0, len(header)+len(ciphertext))
	frame = append(frame, header...)
	frame = append(frame, ciphertext...)
	zeroBytes(header)
	zeroBytes(ciphertext)
	s.nextSend++
	return frame, nil
}

// Open authenticates and decrypts one control message. It rejects frames from
// the wrong role, duplicates, and frames outside the 64-packet replay window.
func (s *Session) Open(frame []byte) ([]byte, error) {
	if s == nil {
		return nil, errSessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errSessionClosed
	}
	if !s.ready {
		return nil, errSessionNotReady
	}
	if len(frame) < sessionFrameHeaderLen+chacha20poly1305.Overhead || len(frame) > sessionMaxFrame {
		return nil, errSessionInvalidFrame
	}
	if subtle.ConstantTimeCompare(frame[:4], sessionMagic[:]) != 1 || frame[4] != sessionVersion ||
		frame[5] != s.rxRole() {
		return nil, errSessionInvalidFrame
	}
	seq := binary.BigEndian.Uint64(frame[6:sessionFrameHeaderLen])
	if !s.sequenceAvailable(seq) {
		return nil, errSessionReplay
	}
	nonce := sessionNonce(s.rxNonceBase, seq)
	aead, err := chacha20poly1305.NewX(s.rxKey)
	if err != nil {
		return nil, errSessionInvalidFrame
	}
	aad := sessionAAD(frame[:sessionFrameHeaderLen], s.contextDigest[:])
	plaintext, err := aead.Open(nil, nonce[:], frame[sessionFrameHeaderLen:], aad)
	zeroBytes(aad)
	if err != nil {
		return nil, errSessionInvalidFrame
	}
	s.markSequence(seq)
	return plaintext, nil
}

// Close clears session key material and makes all subsequent operations fail.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	zeroBytes(s.baseKey)
	zeroBytes(s.helloKey)
	zeroBytes(s.hello)
	zeroBytes(s.challenge[:])
	zeroBytes(s.peer[:])
	zeroBytes(s.txKey)
	zeroBytes(s.rxKey)
	zeroBytes(s.txNonceBase[:])
	zeroBytes(s.rxNonceBase[:])
	s.baseKey = nil
	s.helloKey = nil
	s.hello = nil
	s.txKey = nil
	s.rxKey = nil
	return nil
}

func (s *Session) deriveTrafficLocked() error {
	var hostChallenge, guestChallenge []byte
	if s.role == sessionRoleHost {
		hostChallenge = s.challenge[:]
		guestChallenge = s.peer[:]
	} else {
		hostChallenge = s.peer[:]
		guestChallenge = s.challenge[:]
	}
	h := sha256.New()
	h.Write([]byte("wire-connect/session-salt/v1"))
	writeHashField(h, s.contextDigest[:])
	writeHashField(h, hostChallenge)
	writeHashField(h, guestChallenge)
	salt := h.Sum(nil)
	defer zeroBytes(salt)

	hostToGuestInfo := sessionKDFInfo("wire-connect/session-host-to-guest/v1", s.contextDigest[:])
	hostToGuest, err := deriveHKDF(s.baseKey, salt, hostToGuestInfo, chacha20poly1305.KeySize+sessionNoncePrefixLen)
	if err != nil {
		return err
	}
	guestToHostInfo := sessionKDFInfo("wire-connect/session-guest-to-host/v1", s.contextDigest[:])
	guestToHost, err := deriveHKDF(s.baseKey, salt, guestToHostInfo, chacha20poly1305.KeySize+sessionNoncePrefixLen)
	if err != nil {
		zeroBytes(hostToGuest)
		return err
	}
	if s.role == sessionRoleHost {
		s.txKey = append([]byte(nil), hostToGuest[:chacha20poly1305.KeySize]...)
		s.rxKey = append([]byte(nil), guestToHost[:chacha20poly1305.KeySize]...)
		copy(s.txNonceBase[:], hostToGuest[chacha20poly1305.KeySize:])
		copy(s.rxNonceBase[:], guestToHost[chacha20poly1305.KeySize:])
	} else {
		s.txKey = append([]byte(nil), guestToHost[:chacha20poly1305.KeySize]...)
		s.rxKey = append([]byte(nil), hostToGuest[:chacha20poly1305.KeySize]...)
		copy(s.txNonceBase[:], guestToHost[chacha20poly1305.KeySize:])
		copy(s.rxNonceBase[:], hostToGuest[chacha20poly1305.KeySize:])
	}
	zeroBytes(hostToGuest)
	zeroBytes(guestToHost)
	return nil
}

func (s *Session) txRole() byte {
	return s.role
}

func (s *Session) rxRole() byte {
	if s.role == sessionRoleHost {
		return sessionRoleGuest
	}
	return sessionRoleHost
}

func (s *Session) sequenceAvailable(seq uint64) bool {
	if !s.haveRecv {
		return true
	}
	if seq > s.highest {
		return true
	}
	delta := s.highest - seq
	return delta < sessionReplayWindow && s.recvBits&(uint64(1)<<delta) == 0
}

func (s *Session) markSequence(seq uint64) {
	if !s.haveRecv {
		s.haveRecv = true
		s.highest = seq
		s.recvBits = 1
		return
	}
	if seq > s.highest {
		shift := seq - s.highest
		if shift >= sessionReplayWindow {
			s.recvBits = 1
		} else {
			s.recvBits = (s.recvBits << shift) | 1
		}
		s.highest = seq
		return
	}
	delta := s.highest - seq
	if delta < sessionReplayWindow {
		s.recvBits |= uint64(1) << delta
	}
}

func sessionContextDigest(contextValue string) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte("wire-connect/session-context/v1"))
	writeHashField(h, []byte(contextValue))
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func sessionKDFInfo(label string, contextDigest []byte) []byte {
	info := make([]byte, 0, len(label)+4+len(contextDigest))
	info = append(info, label...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(contextDigest)))
	info = append(info, length[:]...)
	info = append(info, contextDigest...)
	return info
}

func sessionAAD(header, contextDigest []byte) []byte {
	aad := make([]byte, 0, len(header)+len(contextDigest))
	aad = append(aad, header...)
	aad = append(aad, contextDigest...)
	return aad
}

func sessionNonce(prefix [sessionNoncePrefixLen]byte, seq uint64) [chacha20poly1305.NonceSizeX]byte {
	var nonce [chacha20poly1305.NonceSizeX]byte
	copy(nonce[:sessionNoncePrefixLen], prefix[:])
	binary.BigEndian.PutUint64(nonce[sessionNoncePrefixLen:], seq)
	return nonce
}

func isAllZero(value []byte) bool {
	var result byte
	for _, b := range value {
		result |= b
	}
	return result == 0
}
