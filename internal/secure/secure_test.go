package secure

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type channelExchange struct {
	send chan []byte
	recv chan []byte
}

func (e *channelExchange) Send(ctx context.Context, payload []byte) error {
	copyPayload := append([]byte(nil), payload...)
	select {
	case e.send <- copyPayload:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *channelExchange) Receive(ctx context.Context) ([]byte, error) {
	select {
	case payload := <-e.recv:
		return payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func pairExchanges() (*channelExchange, *channelExchange) {
	guestToHost := make(chan []byte, 8)
	hostToGuest := make(chan []byte, 8)
	return &channelExchange{send: hostToGuest, recv: guestToHost},
		&channelExchange{send: guestToHost, recv: hostToGuest}
}

func TestCodeRoundTrip(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(code.Room()) != codeRoomLength || len(code.String()) != codeLength+2 {
		t.Fatalf("unexpected code formatting: room=%q code=%q", code.Room(), code.String())
	}
	if code.Room() != strings.ToLower(code.Room()) || code.String() != strings.ToLower(code.String()) {
		t.Fatalf("code formatting is not canonical lower-case: room=%q code=%q", code.Room(), code.String())
	}
	parsed, err := ParseCode("  " + code.String()[0:4] + "-" + code.String()[5:9] + "-" + code.String()[10:] + "  ")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.String() != code.String() || parsed.Room() != code.Room() {
		t.Fatalf("code did not round-trip: got %q want %q", parsed, code)
	}
	if _, err := ParseCode("ABCD-1234-5678"); !errors.Is(err, errWeakCode) {
		t.Fatalf("weak code accepted: %v", err)
	}
	if _, err := ParseCode("ABCD-IJKL-MNOP"); !errors.Is(err, errInvalidCode) {
		t.Fatalf("ambiguous alphabet accepted: %v", err)
	}
	if PairID(nil) != "" || len(PairID(make([]byte, pairRootLength))) != 64 {
		t.Fatal("unexpected PairID behavior")
	}
}

func TestPairHostGuest(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	hostExchange, guestExchange := pairExchanges()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var (
		hostRoot []byte
		hostErr  error
	)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		hostRoot, hostErr = Pair(ctx, code, true, "HTTPS://Example.COM:443", hostExchange)
	}()
	guestRoot, guestErr := Pair(ctx, code, false, "https://example.com/", guestExchange)
	wg.Wait()
	if hostErr != nil || guestErr != nil {
		t.Fatalf("pair failed: host=%v guest=%v", hostErr, guestErr)
	}
	if len(hostRoot) != pairRootLength || string(hostRoot) != string(guestRoot) {
		t.Fatal("host and guest roots differ")
	}
	if PairID(hostRoot) != PairID(guestRoot) {
		t.Fatal("host and guest PairID differ")
	}
	zeroBytes(hostRoot)
	zeroBytes(guestRoot)
}

func TestPairRejectsContextMismatch(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	hostExchange, guestExchange := pairExchanges()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result := make(chan error, 1)
	go func() {
		_, err := Pair(ctx, code, true, "https://host.example/", hostExchange)
		result <- err
	}()
	if _, err := Pair(ctx, code, false, "https://other.example/", guestExchange); err == nil {
		t.Fatal("context mismatch unexpectedly paired")
	}
	if err := <-result; err == nil {
		t.Fatal("host accepted a context mismatch")
	}
}

func TestPairRejectsWrongCode(t *testing.T) {
	hostCode, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	// Keep the public room the same so this exercises PAKE authentication,
	// rather than an earlier rendezvous-room mismatch.
	guestCode, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	copy(guestCode.raw[:codeRoomLength], hostCode.raw[:codeRoomLength])
	if string(guestCode.raw[codeRoomLength:]) == string(hostCode.raw[codeRoomLength:]) {
		t.Fatal("generated wrong code has the same secret")
	}

	hostExchange, guestExchange := pairExchanges()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	hostDone := make(chan error, 1)
	go func() {
		_, err := Pair(ctx, hostCode, true, "http://127.0.0.1:8765", hostExchange)
		hostDone <- err
	}()
	if _, err := Pair(ctx, guestCode, false, "http://127.0.0.1:8765", guestExchange); err == nil {
		t.Fatal("wrong code unexpectedly paired")
	}
	if err := <-hostDone; err == nil {
		t.Fatal("host accepted wrong code")
	}
}

func TestSessionHandshakeAndReplayWindow(t *testing.T) {
	root := []byte("01234567890123456789012345678901")
	ctxValue := "wire-connect/test-session/v1"
	host, err := NewSession(root, true, ctxValue)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := NewSession(root, false, ctxValue)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	defer guest.Close()
	hostHello, err := host.Hello()
	if err != nil {
		t.Fatal(err)
	}
	guestHello, err := guest.Hello()
	if err != nil {
		t.Fatal(err)
	}
	if err := host.AcceptHello(guestHello); err != nil {
		t.Fatal(err)
	}
	if err := guest.AcceptHello(hostHello); err != nil {
		t.Fatal(err)
	}

	first, err := host.Seal([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := host.Seal([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := guest.Open(second); err != nil || string(got) != "second" {
		t.Fatalf("out-of-order second message failed: %q %v", got, err)
	}
	if got, err := guest.Open(first); err != nil || string(got) != "first" {
		t.Fatalf("out-of-order first message failed: %q %v", got, err)
	}
	if _, err := guest.Open(first); !errors.Is(err, errSessionReplay) {
		t.Fatalf("replayed message accepted: %v", err)
	}

	reply, err := guest.Seal([]byte("reply"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := host.Open(reply); err != nil || string(got) != "reply" {
		t.Fatalf("reverse message failed: %q %v", got, err)
	}
	fresh, err := guest.Seal([]byte("fresh"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), fresh...)
	tampered[len(tampered)-1] ^= 1
	if _, err := host.Open(tampered); !errors.Is(err, errSessionInvalidFrame) {
		t.Fatalf("tampered message returned unexpected error: %v", err)
	}
	if _, err := guest.Open(reply); !errors.Is(err, errSessionInvalidFrame) {
		t.Fatalf("wrong direction message returned unexpected error: %v", err)
	}
	if _, err := host.Open(hostHello); !errors.Is(err, errSessionInvalidFrame) {
		t.Fatalf("hello reflection returned unexpected error: %v", err)
	}
}

func TestSessionRejectsRoleAndContextMismatch(t *testing.T) {
	root := []byte("01234567890123456789012345678901")
	host, err := NewSession(root, true, "context-a")
	if err != nil {
		t.Fatal(err)
	}
	guest, err := NewSession(root, false, "context-b")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	defer guest.Close()
	hostHello, err := host.Hello()
	if err != nil {
		t.Fatal(err)
	}
	guestHello, err := guest.Hello()
	if err != nil {
		t.Fatal(err)
	}
	if err := host.AcceptHello(guestHello); !errors.Is(err, errSessionInvalidHello) {
		t.Fatalf("context mismatch accepted by host: %v", err)
	}
	if err := host.AcceptHello(hostHello); !errors.Is(err, errSessionInvalidHello) {
		t.Fatalf("role reflection accepted by host: %v", err)
	}
	if err := host.AcceptHello(nil); !errors.Is(err, errSessionInvalidHello) {
		t.Fatalf("short hello returned unexpected error: %v", err)
	}
}
