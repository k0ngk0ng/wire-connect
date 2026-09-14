package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/client"
	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/localctl"
)

type statusProfileFixture struct {
	dir     string
	servers []*localctl.Server
}

func newStatusProfileFixture(t *testing.T) *statusProfileFixture {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// Keep Unix socket paths below macOS's sockaddr_un limit even when the
	// repository is checked out at a long absolute path.
	base := filepath.Join(filepath.Dir(file), "..", "..", ".cache", "st")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(base, "p")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "state")
	if err := (config.Store{Dir: dir}).Init(); err != nil {
		_ = os.RemoveAll(root)
		t.Fatal(err)
	}
	fixture := &statusProfileFixture{dir: dir}
	t.Cleanup(func() {
		for _, server := range fixture.servers {
			_ = server.Close()
		}
		_ = os.RemoveAll(root)
	})
	return fixture
}

func (f *statusProfileFixture) add(t *testing.T, name, server string, st client.Status, running bool) {
	t.Helper()
	store := config.Store{Dir: f.dir}
	if err := store.Write("profile-"+name, config.Profile{Server: server}); err != nil {
		t.Fatal(err)
	}
	if !running {
		return
	}
	control, err := localctl.Listen(context.Background(), f.dir, name, func() any { return st }, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.servers = append(f.servers, control)
}

func makeStatus(mode, local, peer string) client.Status {
	return client.Status{
		Running:        true,
		Mode:           mode,
		LocalIP:        local,
		PeerIP:         peer,
		DirectSent:     2048,
		DirectReceived: 1024,
		RelaySent:      512,
		RelayReceived:  256,
		DirectRemote:   "203.0.113.8:34781",
		ModeSince:      time.Date(2026, time.September, 14, 6, 56, 25, 0, time.UTC),
		ModeReason:     mode + "_selected",
		LastHandshake:  time.Date(2026, time.September, 14, 6, 56, 21, 0, time.UTC),
		Updated:        time.Date(2026, time.September, 14, 6, 56, 26, 0, time.UTC),
	}
}

func populatedStatusFixture(t *testing.T) *statusProfileFixture {
	t.Helper()
	f := newStatusProfileFixture(t)
	f.add(t, "default", "https://default.example", makeStatus("direct", "100.64.0.1", "100.64.0.2"), true)
	f.add(t, "office", "https://office.example", makeStatus("direct", "100.64.0.3", "100.64.0.4"), true)
	f.add(t, "relay", "https://relay.example", makeStatus("relay", "100.64.0.5", "100.64.0.6"), true)
	f.add(t, "waiting", "https://waiting.example", makeStatus("none", "100.64.0.7", "100.64.0.8"), true)
	// Keep the profile on disk but do not start its local control endpoint.
	f.add(t, "offline", "https://offline.example", client.Status{}, false)
	return f
}

func runStatus(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	args = append([]string{"status", "--state-dir", dir}, args...)
	var out bytes.Buffer
	err := Run(context.Background(), args, "test", strings.NewReader(""), &out, &bytes.Buffer{})
	return out.String(), err
}

func TestStatusSummarizesAllProfiles(t *testing.T) {
	f := populatedStatusFixture(t)
	text, err := runStatus(t, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Connections: 5 | Direct: 2 | Relay: 1 | Other: 2",
		"Connection: default [DIRECT]",
		"Connection: office [DIRECT]",
		"Connection: relay [RELAY]",
		"Connection: waiting [WAITING]",
		"Connection: offline [UNAVAILABLE]",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("status output missing %q:\n%s", want, text)
		}
	}
}

func TestStatusSelectsNamedProfile(t *testing.T) {
	f := populatedStatusFixture(t)
	text, err := runStatus(t, f.dir, "--name", "relay")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Connection: relay [RELAY]") {
		t.Fatalf("named status missing relay:\n%s", text)
	}
	if strings.Contains(text, "Connection: default") || strings.Contains(text, "Connection: office") || strings.Contains(text, "Connection: offline") {
		t.Fatalf("named status included another profile:\n%s", text)
	}
}

func TestStatusJSONKeepsSingleProfileShape(t *testing.T) {
	f := populatedStatusFixture(t)
	text, err := runStatus(t, f.dir, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var st client.Status
	if err := json.Unmarshal([]byte(text), &st); err != nil {
		t.Fatalf("legacy JSON shape: %v (%s)", err, text)
	}
	if st.Mode != "direct" || st.LocalIP != "100.64.0.1" || st.DirectSent != 2048 {
		t.Fatalf("unexpected default status: %+v", st)
	}
}

func TestStatusJSONAllProfilesIncludesUnavailableProfile(t *testing.T) {
	f := populatedStatusFixture(t)
	text, err := runStatus(t, f.dir, "--all", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []connectionStatus
	if err := json.Unmarshal([]byte(text), &rows); err != nil {
		t.Fatalf("all JSON shape: %v (%s)", err, text)
	}
	if len(rows) != 5 {
		t.Fatalf("profile count = %d, want 5: %+v", len(rows), rows)
	}
	byName := make(map[string]connectionStatus, len(rows))
	for _, row := range rows {
		byName[row.Name] = row
	}
	for _, name := range []string{"default", "office", "relay", "waiting", "offline"} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("missing profile %q: %+v", name, rows)
		}
	}
	if byName["default"].Status.Mode != "direct" {
		t.Fatalf("default mode = %q, want direct", byName["default"].Status.Mode)
	}
	if byName["relay"].Status.Mode != "relay" {
		t.Fatalf("relay mode = %q, want relay", byName["relay"].Status.Mode)
	}
	if byName["waiting"].Status.Mode != "none" {
		t.Fatalf("waiting mode = %q, want none", byName["waiting"].Status.Mode)
	}
	if byName["offline"].Error == "" {
		t.Fatal("offline profile has no status error")
	}
}

func TestPrintConnectionsColorAndNoColor(t *testing.T) {
	rows := []connectionStatus{
		{Name: "direct", Status: makeStatus("direct", "100.64.0.1", "100.64.0.2")},
		{Name: "relay", Status: makeStatus("relay", "100.64.0.3", "100.64.0.4")},
	}
	var plain, colored bytes.Buffer
	printConnections(&plain, rows, false)
	printConnections(&colored, rows, true)
	if strings.Contains(plain.String(), "\x1b[") {
		t.Fatalf("no-color output contains ANSI escape: %q", plain.String())
	}
	if !strings.Contains(colored.String(), "\x1b[1mWIRE CONNECT\x1b[0m") {
		t.Fatalf("color output has no colored title: %q", colored.String())
	}
	if !strings.Contains(colored.String(), "\x1b[1;32m[DIRECT]\x1b[0m") || !strings.Contains(colored.String(), "\x1b[1;33m[RELAY]\x1b[0m") {
		t.Fatalf("color output has no per-path colors: %q", colored.String())
	}
}

func TestPrintConnectionsHistoryCountersDoNotChangeCurrentMode(t *testing.T) {
	st := makeStatus("direct", "100.64.0.1", "100.64.0.2")
	// Relay counters can retain traffic from an earlier path after the
	// connection upgrades to direct. The selected mode must still be direct.
	st.DirectSent = 4 << 10
	st.DirectReceived = 3 << 10
	st.RelaySent = 2 << 10
	st.RelayReceived = 1 << 10
	row := connectionStatus{Name: "upgraded", Status: st}
	if got := connectionMode(row); got != "DIRECT" {
		t.Fatalf("mode with historical relay traffic = %q, want DIRECT", got)
	}
	var out bytes.Buffer
	printConnections(&out, []connectionStatus{row}, false)
	text := out.String()
	if !strings.Contains(text, "Connection: upgraded [DIRECT]") {
		t.Fatalf("current mode missing from output: %s", text)
	}
	if !strings.Contains(text, "Direct:  ↑ 4.0 KiB sent   ↓ 3.0 KiB received") || !strings.Contains(text, "Relay:   ↑ 2.0 KiB sent   ↓ 1.0 KiB received") {
		t.Fatalf("historical per-path counters missing from output: %s", text)
	}
}
