package secure

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bytemare/opaque"
	"golang.org/x/crypto/hkdf"
)

// Exchange is the reliable, ordered message channel used for pairing. The
// transport is deliberately kept outside this package: it may be a WSS
// control stream or a test channel, but it must not expose pairing messages to
// an untrusted caller after the channel is established.
type Exchange interface {
	Send(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
}

const (
	pairVersion       = 1
	pairHeaderLength  = 8
	maxPairPayload    = 16 << 10
	maxPairFrame      = pairHeaderLength + maxPairPayload
	maxPairContextLen = 1024
	pairTimeout       = 90 * time.Second
	pairRootLength    = 32
	pairConfirmLength = sha256.Size
)

const (
	pairTypeKE1      = 1
	pairTypeKE2      = 2
	pairTypeKE3      = 3
	pairTypeGuestMAC = 4
	pairTypeHostMAC  = 5
)

var pairMagic = [4]byte{'W', 'C', 'P', '1'}

var (
	errPairInvalidFrame = errors.New("wire-connect: invalid pairing frame")
	errPairState        = errors.New("wire-connect: invalid pairing state")
)

const (
	hostRoleID  = "wire-connect/role/host/v1"
	guestRoleID = "wire-connect/role/guest/v1"
)

// PairContext returns the canonical transcript context for a pairing room.
// Both peers must use this exact value when constructing a Session. The room
// identifier is public and only selects the rendezvous mailbox; the code's
// secret never appears in this context or in any frame.
func PairContext(server string, code Code) (string, error) {
	if !code.valid() {
		return "", errInvalidCode
	}
	canonical, err := canonicalServerURL(server)
	if err != nil {
		return "", err
	}

	// Length-prefix every variable field so that the context cannot have
	// concatenation ambiguities. The role names are ordered and are therefore
	// identical for the host and guest configurations.
	var b strings.Builder
	b.WriteString("wire-connect/opaque-context/v1")
	writeContextField(&b, canonical)
	writeContextField(&b, code.Room())
	writeContextField(&b, hostRoleID)
	writeContextField(&b, guestRoleID)
	if b.Len() > maxPairContextLen {
		return "", errors.New("wire-connect: pairing context exceeds size limit")
	}

	return b.String(), nil
}

func writeContextField(b *strings.Builder, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value))) // bounded by URL/context validation
	b.Write(length[:])
	b.WriteString(value)
}

func canonicalServerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return "", errors.New("wire-connect: invalid server URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" {
		return "", errors.New("wire-connect: invalid server URL")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https", "ws", "wss":
	default:
		return "", fmt.Errorf("wire-connect: unsupported server URL scheme %q", u.Scheme)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", errors.New("wire-connect: server URL cannot contain credentials, query, or fragment")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.ContainsAny(host, "\x00\r\n") {
		return "", errors.New("wire-connect: invalid server URL host")
	}
	if scheme == "http" || scheme == "ws" {
		// Plaintext control traffic is only acceptable for a loopback test
		// server. Hostnames such as localhost are intentionally rejected: the
		// context must identify the literal endpoint and must not depend on DNS.
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", errors.New("wire-connect: plaintext server URL must use a loopback IP")
		}
	}
	port := u.Port()
	if port != "" {
		portNumber, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil {
			return "", errors.New("wire-connect: invalid server URL port")
		}
		port = strconv.FormatUint(portNumber, 10)
	}
	if ((scheme == "http" || scheme == "ws") && port == "80") || ((scheme == "https" || scheme == "wss") && port == "443") {
		port = ""
	}
	if port == "" {
		u.Host = host
		if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		}
	} else {
		u.Host = net.JoinHostPort(host, port)
	}
	u.Scheme = scheme
	if u.Path == "" {
		u.Path = "/"
	}
	u.RawPath = ""
	return u.String(), nil
}

// Pair performs one authenticated host/guest pairing. A host creates the
// OPAQUE registration record locally from code and keeps it only for this
// call. A guest performs the OPAQUE login against that ephemeral record. The
// public rendezvous server only carries the opaque protocol frames.
func Pair(ctx context.Context, code Code, host bool, server string, exchange Exchange) (root []byte, err error) {
	if ctx == nil {
		return nil, errors.New("wire-connect: nil pairing context")
	}
	if exchange == nil {
		return nil, errors.New("wire-connect: nil pairing exchange")
	}
	if !code.valid() {
		return nil, errInvalidCode
	}
	pairCtx, cancel := context.WithTimeout(ctx, pairTimeout)
	defer cancel()
	contextValue, err := PairContext(server, code)
	if err != nil {
		return nil, err
	}

	// OPAQUE validates inputs aggressively, but this boundary also protects the
	// long-running connect process from a malformed third-party message or a
	// panic in a dependency. No secret is included in the panic error.
	defer func() {
		if recovered := recover(); recovered != nil {
			zeroBytes(root)
			root = nil
			err = errors.New("wire-connect: pairing protocol failure")
		}
	}()

	if host {
		return pairHost(pairCtx, code, exchange, contextValue)
	}
	return pairGuest(pairCtx, code, exchange, contextValue)
}

func pairHost(ctx context.Context, code Code, exchange Exchange, contextValue string) ([]byte, error) {
	conf := opaque.DefaultConfiguration()
	conf.Context = []byte(contextValue)
	server, err := conf.Server()
	if err != nil {
		return nil, fmt.Errorf("wire-connect: initialize OPAQUE server: %w", err)
	}
	serverPrivate, serverPublic := conf.KeyGen()
	keyMaterial := &opaque.ServerKeyMaterial{
		Identity:       []byte(hostRoleID),
		PrivateKey:     serverPrivate,
		PublicKeyBytes: serverPublic.Encode(),
		OPRFGlobalSeed: conf.GenerateOPRFSeed(),
	}
	defer keyMaterial.Flush()
	if err := server.SetKeyMaterial(keyMaterial); err != nil {
		return nil, fmt.Errorf("wire-connect: initialize OPAQUE key material: %w", err)
	}

	// Build the ephemeral registration record entirely locally. The record is
	// never passed through Exchange and is discarded with the host call.
	registrationClient, err := conf.Client()
	if err != nil {
		return nil, fmt.Errorf("wire-connect: initialize OPAQUE registration client: %w", err)
	}
	password := code.secretBytes()
	defer zeroBytes(password)
	registrationRequest, err := registrationClient.RegistrationInit(password)
	if err != nil {
		registrationClient.ClearState()
		return nil, fmt.Errorf("wire-connect: initialize pairing registration: %w", err)
	}
	registrationResponse, err := server.RegistrationResponse(registrationRequest, []byte(guestRoleID), nil)
	if err != nil {
		registrationClient.ClearState()
		return nil, fmt.Errorf("wire-connect: create pairing registration: %w", err)
	}
	registrationRecord, _, err := registrationClient.RegistrationFinalize(
		registrationResponse,
		[]byte(guestRoleID),
		[]byte(hostRoleID),
	)
	registrationClient.ClearState()
	if err != nil {
		return nil, fmt.Errorf("wire-connect: finalize pairing registration: %w", err)
	}
	record := &opaque.ClientRecord{
		RegistrationRecord:   registrationRecord,
		CredentialIdentifier: []byte(guestRoleID),
		ClientIdentity:       []byte(guestRoleID),
	}
	defer clearRegistrationRecord(record)

	ke1Frame, ke1Payload, err := receivePairFrame(ctx, exchange, pairTypeKE1)
	if err != nil {
		return nil, err
	}
	ke1, err := server.Deserialize.KE1(ke1Payload)
	if err != nil {
		return nil, fmt.Errorf("wire-connect: invalid guest login request: %w", err)
	}
	ke2, serverOutput, err := server.GenerateKE2(ke1, record)
	if err != nil {
		return nil, fmt.Errorf("wire-connect: create guest login response: %w", err)
	}
	if serverOutput == nil || len(serverOutput.SessionSecret) == 0 || len(serverOutput.ClientMAC) == 0 {
		return nil, errors.New("wire-connect: OPAQUE returned incomplete server output")
	}
	defer zeroBytes(serverOutput.SessionSecret)
	defer zeroBytes(serverOutput.ClientMAC)
	ke2Payload := ke2.Serialize()
	if err := sendPairFrame(ctx, exchange, pairTypeKE2, ke2Payload); err != nil {
		zeroBytes(ke2Payload)
		return nil, err
	}
	ke3Frame, ke3Payload, err := receivePairFrame(ctx, exchange, pairTypeKE3)
	if err != nil {
		zeroBytes(ke2Payload)
		return nil, err
	}
	ke3, err := server.Deserialize.KE3(ke3Payload)
	if err != nil {
		zeroBytes(ke2Payload)
		zeroBytes(ke3Payload)
		return nil, fmt.Errorf("wire-connect: invalid guest login confirmation: %w", err)
	}
	if err := server.LoginFinish(ke3, serverOutput.ClientMAC); err != nil {
		zeroBytes(ke2Payload)
		zeroBytes(ke3Payload)
		return nil, fmt.Errorf("wire-connect: guest authentication failed: %w", err)
	}

	transcript := pairTranscript(contextValue, ke1Frame, appendPairFrame(pairTypeKE2, ke2Payload), ke3Frame)
	root, err := derivePairRoot(serverOutput.SessionSecret, transcript, contextValue)
	zeroBytes(serverOutput.SessionSecret)
	zeroBytes(serverOutput.ClientMAC)
	zeroBytes(ke1Payload)
	zeroBytes(ke2Payload)
	zeroBytes(ke3Payload)
	if err != nil {
		return nil, err
	}

	guestMACFrame, _, err := receivePairFrame(ctx, exchange, pairTypeGuestMAC)
	if err != nil {
		zeroBytes(root)
		return nil, err
	}
	if len(guestMACFrame) != pairHeaderLength+pairConfirmLength {
		zeroBytes(root)
		return nil, errPairInvalidFrame
	}
	guestMAC := guestMACFrame[pairHeaderLength:]
	expectedGuestMAC := pairConfirmation(root, "guest", transcript)
	if !hmac.Equal(guestMAC, expectedGuestMAC) {
		zeroBytes(root)
		return nil, errors.New("wire-connect: guest key confirmation failed")
	}
	hostMAC := pairConfirmation(root, "host", transcript)
	if err := sendPairFrame(ctx, exchange, pairTypeHostMAC, hostMAC); err != nil {
		zeroBytes(root)
		return nil, err
	}
	zeroBytes(hostMAC)
	return root, nil
}

func pairGuest(ctx context.Context, code Code, exchange Exchange, contextValue string) ([]byte, error) {
	conf := opaque.DefaultConfiguration()
	conf.Context = []byte(contextValue)
	client, err := conf.Client()
	if err != nil {
		return nil, fmt.Errorf("wire-connect: initialize OPAQUE client: %w", err)
	}
	defer client.ClearState()
	password := code.secretBytes()
	defer zeroBytes(password)
	ke1, err := client.GenerateKE1(password)
	if err != nil {
		return nil, fmt.Errorf("wire-connect: initialize guest login: %w", err)
	}
	ke1Payload := ke1.Serialize()
	if err := sendPairFrame(ctx, exchange, pairTypeKE1, ke1Payload); err != nil {
		zeroBytes(ke1Payload)
		return nil, err
	}
	ke2Frame, ke2Payload, err := receivePairFrame(ctx, exchange, pairTypeKE2)
	if err != nil {
		zeroBytes(ke1Payload)
		return nil, err
	}
	ke2, err := client.Deserialize.KE2(ke2Payload)
	if err != nil {
		zeroBytes(ke1Payload)
		zeroBytes(ke2Payload)
		return nil, fmt.Errorf("wire-connect: invalid host login response: %w", err)
	}
	ke3, sessionSecret, _, err := client.GenerateKE3(ke2, []byte(guestRoleID), []byte(hostRoleID))
	defer zeroBytes(sessionSecret)
	if err != nil {
		zeroBytes(ke1Payload)
		zeroBytes(ke2Payload)
		return nil, fmt.Errorf("wire-connect: host authentication failed: %w", err)
	}
	ke3Payload := ke3.Serialize()
	if err := sendPairFrame(ctx, exchange, pairTypeKE3, ke3Payload); err != nil {
		zeroBytes(sessionSecret)
		zeroBytes(ke1Payload)
		zeroBytes(ke2Payload)
		zeroBytes(ke3Payload)
		return nil, err
	}

	transcript := pairTranscript(contextValue, appendPairFrame(pairTypeKE1, ke1Payload), ke2Frame, appendPairFrame(pairTypeKE3, ke3Payload))
	root, err := derivePairRoot(sessionSecret, transcript, contextValue)
	zeroBytes(sessionSecret)
	zeroBytes(ke1Payload)
	zeroBytes(ke2Payload)
	zeroBytes(ke3Payload)
	if err != nil {
		return nil, err
	}
	guestMAC := pairConfirmation(root, "guest", transcript)
	if err := sendPairFrame(ctx, exchange, pairTypeGuestMAC, guestMAC); err != nil {
		zeroBytes(root)
		zeroBytes(guestMAC)
		return nil, err
	}
	zeroBytes(guestMAC)
	hostMACFrame, _, err := receivePairFrame(ctx, exchange, pairTypeHostMAC)
	if err != nil {
		zeroBytes(root)
		return nil, err
	}
	if len(hostMACFrame) != pairHeaderLength+pairConfirmLength {
		zeroBytes(root)
		return nil, errPairInvalidFrame
	}
	expectedHostMAC := pairConfirmation(root, "host", transcript)
	if !hmac.Equal(hostMACFrame[pairHeaderLength:], expectedHostMAC) {
		zeroBytes(root)
		return nil, errors.New("wire-connect: host key confirmation failed")
	}
	return root, nil
}

func appendPairFrame(kind byte, payload []byte) []byte {
	frame := make([]byte, pairHeaderLength+len(payload))
	copy(frame[:4], pairMagic[:])
	frame[4] = pairVersion
	frame[5] = kind
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[pairHeaderLength:], payload)
	return frame
}

func sendPairFrame(ctx context.Context, exchange Exchange, kind byte, payload []byte) error {
	if len(payload) > maxPairPayload || kind == 0 {
		return errPairInvalidFrame
	}
	frame := appendPairFrame(kind, payload)
	defer zeroBytes(frame)
	if err := exchange.Send(ctx, frame); err != nil {
		return fmt.Errorf("wire-connect: send pairing frame: %w", err)
	}
	return nil
}

func receivePairFrame(ctx context.Context, exchange Exchange, expected byte) (frame, payload []byte, err error) {
	frame, err = exchange.Receive(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("wire-connect: receive pairing frame: %w", err)
	}
	frame = append([]byte(nil), frame...)
	if len(frame) < pairHeaderLength || len(frame) > maxPairFrame || !hmac.Equal(frame[:4], pairMagic[:]) ||
		frame[4] != pairVersion || frame[5] != expected ||
		int(binary.BigEndian.Uint16(frame[6:8])) != len(frame)-pairHeaderLength {
		return nil, nil, errPairInvalidFrame
	}
	payload = append([]byte(nil), frame[pairHeaderLength:]...)
	return frame, payload, nil
}

func pairTranscript(contextValue string, frames ...[]byte) []byte {
	h := sha256.New()
	h.Write([]byte("wire-connect/pair-transcript/v1"))
	writeHashField(h, []byte(contextValue))
	for _, frame := range frames {
		writeHashField(h, frame)
	}
	return h.Sum(nil)
}

func writeHashField(w io.Writer, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = w.Write(length[:])
	_, _ = w.Write(value)
}

func derivePairRoot(sessionSecret, transcript []byte, contextValue string) ([]byte, error) {
	if len(sessionSecret) == 0 || len(transcript) != sha256.Size {
		return nil, errors.New("wire-connect: invalid OPAQUE session secret")
	}
	info := []byte("wire-connect/pair-root/v1\x00" + contextValue)
	return deriveHKDF(sessionSecret, transcript, info, pairRootLength)
}

func pairConfirmation(root []byte, side string, transcript []byte) []byte {
	mac := hmac.New(sha256.New, root)
	mac.Write([]byte("wire-connect/pair-confirm/v1\x00"))
	writeHashField(mac, []byte(side))
	writeHashField(mac, transcript)
	return mac.Sum(nil)
}

func deriveHKDF(secret, salt, info []byte, length int) ([]byte, error) {
	if len(secret) == 0 || length <= 0 || length > 1<<20 {
		return nil, errors.New("wire-connect: invalid key derivation input")
	}
	reader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(reader, key); err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("wire-connect: derive key: %w", err)
	}
	return key, nil
}

func clearRegistrationRecord(record *opaque.ClientRecord) {
	if record == nil {
		return
	}
	if record.RegistrationRecord != nil {
		zeroBytes(record.MaskingKey)
		zeroBytes(record.Envelope)
	}
	zeroBytes(record.CredentialIdentifier)
	zeroBytes(record.ClientIdentity)
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

// PairID derives an opaque, stable identifier from a successful root secret.
// It returns an empty string for an empty secret.
func PairID(secret []byte) string {
	if len(secret) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("wire-connect/pair-id/v1"))
	return hex.EncodeToString(mac.Sum(nil))
}
