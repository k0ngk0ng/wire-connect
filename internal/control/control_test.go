package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const testEnrollment = "test-enrollment-credential"

type testService struct {
	server *Server
	http   *httptest.Server
	state  string
}

func newTestService(t *testing.T, ttl time.Duration) *testService {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(".cache", "tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	state, err := os.MkdirTemp(filepath.Join(".cache", "tmp"), "control-")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{StateDir: state, EnrollmentToken: testEnrollment, RoomTTL: ttl})
	if err != nil {
		_ = os.RemoveAll(state)
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		ts.Close()
		_ = s.Close()
		_ = os.RemoveAll(state)
	})
	return &testService{server: s, http: ts, state: state}
}

func login(t *testing.T, base, enrollment string) LoginResponse {
	t.Helper()
	var out LoginResponse
	status := doJSON(t, http.MethodPost, base+"/v1/login", "", LoginRequest{Token: enrollment}, &out)
	if status != http.StatusCreated {
		t.Fatalf("login status = %d", status)
	}
	if out.Token == "" || !validDeviceID(out.DeviceID) {
		t.Fatalf("invalid login response: %#v", out)
	}
	return out
}

func doJSON(t *testing.T, method, url, token string, in, out any) int {
	t.Helper()
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		body = strings.NewReader(string(data))
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s response: %v", url, err)
		}
	}
	return resp.StatusCode
}

func dialSocket(t *testing.T, base, token, path string) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(base, "http") + path
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{
		"Authorization": []string{"Bearer " + token},
	}})
	if err != nil {
		if resp != nil {
			t.Fatalf("dial %s: %v (status %s)", path, err, resp.Status)
		}
		t.Fatalf("dial %s: %v", path, err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

func readMessage(t *testing.T, conn *websocket.Conn) Message {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var msg Message
	if err := wsjson.Read(ctx, conn, &msg); err != nil {
		t.Fatal(err)
	}
	return msg
}

func expectConnected(t *testing.T, conn *websocket.Conn, want bool) {
	t.Helper()
	msg := readMessage(t, conn)
	if msg.Kind != "peer" {
		t.Fatalf("peer event kind = %q", msg.Kind)
	}
	var payload struct {
		Connected bool `json:"connected"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Connected != want {
		t.Fatalf("peer connected = %v, want %v", payload.Connected, want)
	}
}

func TestLoginAuthAndStateRestart(t *testing.T) {
	svc := newTestService(t, time.Minute)
	resp, err := http.Get(svc.http.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/login", "", LoginRequest{Token: "wrong"}, &map[string]any{}); status != http.StatusUnauthorized {
		t.Fatalf("bad login status = %d", status)
	}
	device := login(t, svc.http.URL, testEnrollment)
	if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/rooms", "bad", CreateRoomRequest{ID: "abcd"}, &map[string]any{}); status != http.StatusUnauthorized {
		t.Fatalf("bad auth status = %d", status)
	}
	var roomResp CreateRoomResponse
	if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/rooms", device.Token, CreateRoomRequest{ID: "abcd"}, &roomResp); status != http.StatusCreated {
		t.Fatalf("create room status = %d", status)
	}
	if roomResp.ID != "abcd" {
		t.Fatalf("room ID = %q", roomResp.ID)
	}

	data, err := os.ReadFile(filepath.Join(svc.state, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), device.Token) || strings.Contains(string(data), testEnrollment) {
		t.Fatal("state file contains plaintext credential")
	}
	info, err := os.Stat(filepath.Join(svc.state, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state mode = %o", info.Mode().Perm())
	}

	_ = svc.server.Close()
	restarted, err := New(Config{StateDir: svc.state})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restartedHTTP := httptest.NewServer(restarted.Handler())
	defer restartedHTTP.Close()
	var generated CreateRoomResponse
	if status := doJSON(t, http.MethodPost, restartedHTTP.URL+"/v1/rooms", device.Token, CreateRoomRequest{ID: "efgh"}, &generated); status != http.StatusCreated {
		t.Fatalf("restarted auth status = %d", status)
	}
}

func TestRoomExpiryAndThirdPartyRejection(t *testing.T) {
	svc := newTestService(t, 5*time.Second)
	a := login(t, svc.http.URL, testEnrollment)
	b := login(t, svc.http.URL, testEnrollment)
	c := login(t, svc.http.URL, testEnrollment)
	var room CreateRoomResponse
	if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/rooms", a.Token, CreateRoomRequest{ID: "abcd"}, &room); status != http.StatusCreated {
		t.Fatalf("room status = %d", status)
	}
	host := dialSocket(t, svc.http.URL, a.Token, "/v1/rooms/abcd/socket?role=host")
	guest := dialSocket(t, svc.http.URL, b.Token, "/v1/rooms/abcd/socket?role=guest")
	expectConnected(t, host, true)
	expectConnected(t, guest, true)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := wsjson.Write(ctx, host, Message{Kind: "pake", Payload: json.RawMessage(`{"n":1}`)}); err != nil {
		t.Fatal(err)
	}
	cancel()
	got := readMessage(t, guest)
	if got.Kind != "pake" || string(got.Payload) != `{"n":1}` {
		t.Fatalf("forwarded message = %#v", got)
	}

	// The slot is locked to the first guest identity and rejects both a third
	// device and a concurrent second socket for the existing guest.
	url := "ws" + strings.TrimPrefix(svc.http.URL, "http") + "/v1/rooms/abcd/socket?role=guest"
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	_, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + c.Token}}})
	cancel()
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("third guest result err=%v resp=%v", err, resp)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	_, resp, err = websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + b.Token}}})
	cancel()
	if err == nil || resp == nil || resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate guest result err=%v resp=%v", err, resp)
	}

	_ = guest.CloseNow()
	expectConnected(t, host, false)
	deadline := time.Now().Add(time.Second)
	var reconnected *websocket.Conn
	for time.Now().Before(deadline) {
		ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
		candidate, _, dialErr := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + b.Token}}})
		cancel()
		if dialErr == nil {
			reconnected = candidate
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reconnected == nil {
		t.Fatal("guest did not reconnect")
	}
	defer reconnected.CloseNow()
	expectConnected(t, host, true)
	expectConnected(t, reconnected, true)

	expiry := newTestService(t, 40*time.Millisecond)
	expiryHost := login(t, expiry.http.URL, testEnrollment)
	if status := doJSON(t, http.MethodPost, expiry.http.URL+"/v1/rooms", expiryHost.Token, CreateRoomRequest{ID: "efgh"}, &map[string]any{}); status != http.StatusCreated {
		t.Fatalf("second room status = %d", status)
	}
	time.Sleep(70 * time.Millisecond)
	if status := doJSON(t, http.MethodPost, expiry.http.URL+"/v1/rooms", expiryHost.Token, CreateRoomRequest{ID: "efgh"}, &map[string]any{}); status != http.StatusCreated {
		t.Fatalf("expired room recreation status = %d", status)
	}
}

func TestCommitPairRecoveryAndRelayRevoke(t *testing.T) {
	svc := newTestService(t, time.Minute)
	a := login(t, svc.http.URL, testEnrollment)
	b := login(t, svc.http.URL, testEnrollment)
	if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/rooms", a.Token, CreateRoomRequest{ID: "abcd"}, &map[string]any{}); status != http.StatusCreated {
		t.Fatalf("room status = %d", status)
	}
	host := dialSocket(t, svc.http.URL, a.Token, "/v1/rooms/abcd/socket?role=host")
	guest := dialSocket(t, svc.http.URL, b.Token, "/v1/rooms/abcd/socket?role=guest")
	expectConnected(t, host, true)
	expectConnected(t, guest, true)
	pairID := strings.Repeat("a", 64)
	var result CommitResponse
	if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/rooms/abcd/commit", a.Token, CommitRequest{PairID: pairID}, &result); status != http.StatusOK || result.Committed {
		t.Fatalf("first commit status=%d result=%#v", status, result)
	}
	if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/rooms/abcd/commit", b.Token, CommitRequest{PairID: pairID}, &result); status != http.StatusOK || !result.Committed {
		t.Fatalf("second commit status=%d result=%#v", status, result)
	}
	if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/rooms/abcd/commit", a.Token, CommitRequest{PairID: pairID}, &result); status != http.StatusOK || !result.Committed {
		t.Fatalf("idempotent commit status=%d result=%#v", status, result)
	}

	keys := make([]string, 0, maxRelayKeys)
	for i := 0; i < maxRelayKeys; i++ {
		key := strings.Repeat(string("abcdef"[i]), 64)
		keys = append(keys, key)
		if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/relay/register", a.Token, RelayRegisterRequest{Key: key}, &RelayRegisterResponse{}); status != http.StatusOK {
			t.Fatalf("relay register %d status = %d", i, status)
		}
		if !svc.server.AllowedRelayKey(key) {
			t.Fatalf("relay key %d not allowed", i)
		}
	}
	if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/relay/register", a.Token, RelayRegisterRequest{Key: strings.Repeat("f", 64)}, &map[string]any{}); status != http.StatusTooManyRequests {
		t.Fatalf("fifth relay status = %d", status)
	}
	if err := svc.server.RevokeDevice(a.DeviceID); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if svc.server.AllowedRelayKey(key) {
			t.Fatal("revoked relay key still allowed")
		}
	}
	if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/rooms", a.Token, CreateRoomRequest{ID: "efgh"}, &map[string]any{}); status != http.StatusUnauthorized {
		t.Fatalf("revoked device status = %d", status)
	}

	_ = host.CloseNow()
	_ = guest.CloseNow()
	_ = svc.server.Close()
	restarted, err := New(Config{StateDir: svc.state})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restartedHTTP := httptest.NewServer(restarted.Handler())
	defer restartedHTTP.Close()
	// Pair state survived the restart.  The revoked host remains forbidden,
	// while the guest can still authenticate to the pair endpoint.
	if status := doJSON(t, http.MethodGet, restartedHTTP.URL+"/v1/pairs/"+pairID+"/socket", a.Token, nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("revoked pair HTTP status = %d", status)
	}
	url := "ws" + strings.TrimPrefix(restartedHTTP.URL, "http") + "/v1/pairs/" + pairID + "/socket"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	guestPair, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + b.Token}}})
	cancel()
	if err != nil || resp == nil || guestPair == nil {
		t.Fatalf("pair recovery dial err=%v resp=%v", err, resp)
	}
	_ = guestPair.CloseNow()
}

func TestStatePathSecurity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs are not represented by Unix mode bits")
	}
	if err := os.MkdirAll(filepath.Join(".cache", "tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	state, err := os.MkdirTemp(filepath.Join(".cache", "tmp"), "control-security-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(state)
	if err := os.Chmod(state, 0750); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{StateDir: state, EnrollmentToken: testEnrollment}); !errors.Is(err, ErrStateInsecure) {
		t.Fatalf("insecure directory error = %v", err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{StateDir: state, EnrollmentToken: testEnrollment})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	stateFile := filepath.Join(state, "state.json")
	if err := os.Chmod(stateFile, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{StateDir: state, EnrollmentToken: testEnrollment}); !errors.Is(err, ErrStateInsecure) {
		t.Fatalf("insecure file error = %v", err)
	}
}

func TestStateDirectorySingleInstanceLock(t *testing.T) {
	svc := newTestService(t, time.Minute)
	if _, err := New(Config{StateDir: svc.state, EnrollmentToken: testEnrollment}); !errors.Is(err, ErrStateLocked) {
		t.Fatalf("second server error = %v, want ErrStateLocked", err)
	}
	if err := svc.server.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(Config{StateDir: svc.state})
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMessageTokenBucket(t *testing.T) {
	bucket := newTokenBucket(32, 64)
	for i := 0; i < 64; i++ {
		if !bucket.allow() {
			t.Fatalf("burst frame %d was rejected", i)
		}
	}
	if bucket.allow() {
		t.Fatal("frame above burst was accepted")
	}
}

func TestWebSocketOutlivesHTTPRequestContext(t *testing.T) {
	oldTimeout := requestTimeout
	requestTimeout = 40 * time.Millisecond
	defer func() { requestTimeout = oldTimeout }()

	svc := newTestService(t, time.Minute)
	a := login(t, svc.http.URL, testEnrollment)
	b := login(t, svc.http.URL, testEnrollment)
	if status := doJSON(t, http.MethodPost, svc.http.URL+"/v1/rooms", a.Token, CreateRoomRequest{ID: "abcd"}, &CreateRoomResponse{}); status != http.StatusCreated {
		t.Fatalf("room status = %d", status)
	}
	host := dialSocket(t, svc.http.URL, a.Token, "/v1/rooms/abcd/socket?role=host")
	time.Sleep(100 * time.Millisecond)
	guest := dialSocket(t, svc.http.URL, b.Token, "/v1/rooms/abcd/socket?role=guest")
	expectConnected(t, host, true)
	expectConnected(t, guest, true)
}
