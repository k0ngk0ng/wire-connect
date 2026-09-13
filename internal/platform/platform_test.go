package platform

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

func TestNormalizeConfig(t *testing.T) {
	valid := Config{
		Name:  testInterfaceName(),
		Local: netip.MustParseAddr("100.64.0.1"),
		Peer:  netip.MustParseAddr("100.64.0.2"),
	}
	normalized, err := normalizeConfig(valid)
	if err != nil {
		t.Fatalf("normalize valid config: %v", err)
	}
	if normalized.MTU != DefaultMTU {
		t.Fatalf("default MTU = %d, want %d", normalized.MTU, DefaultMTU)
	}

	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{
			name: "empty name",
			edit: func(cfg *Config) { cfg.Name = "" },
			want: "invalid interface name",
		},
		{
			name: "command injection in name",
			edit: func(cfg *Config) { cfg.Name = "wc0;touch" },
			want: "invalid interface name",
		},
		{
			name: "name too long",
			edit: func(cfg *Config) { cfg.Name = "wireconnect012345" },
			want: "invalid interface name",
		},
		{
			name: "IPv6 local",
			edit: func(cfg *Config) { cfg.Local = netip.MustParseAddr("2001:db8::1") },
			want: "local address must be a valid IPv4",
		},
		{
			name: "unspecified peer",
			edit: func(cfg *Config) { cfg.Peer = netip.MustParseAddr("0.0.0.0") },
			want: "peer address 0.0.0.0 is not a usable unicast",
		},
		{
			name: "limited broadcast peer",
			edit: func(cfg *Config) { cfg.Peer = netip.MustParseAddr("255.255.255.255") },
			want: "peer address 255.255.255.255 is not a usable unicast",
		},
		{
			name: "same endpoints",
			edit: func(cfg *Config) { cfg.Peer = cfg.Local },
			want: "local and peer addresses must differ",
		},
		{
			name: "MTU too small",
			edit: func(cfg *Config) { cfg.MTU = minMTU - 1 },
			want: "outside",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.edit(&cfg)
			if _, err := normalizeConfig(cfg); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("normalize error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestFormatCommandQuotesArguments(t *testing.T) {
	got := formatCommand("ip", []string{"addr", "add", "100.64.0.1/32", "dev", "wc0"})
	want := `ip "addr" "add" "100.64.0.1/32" "dev" "wc0"`
	if got != want {
		t.Fatalf("formatCommand() = %q, want %q", got, want)
	}
}

func TestRouteParsersSkipDefaultsAndDetectOverlap(t *testing.T) {
	linuxJSON := []byte(`[
		{"dst":"default","gateway":"192.0.2.1"},
		{"dst":"100.64.0.0/10","dev":"en0"},
		{"dst":"192.0.2.44/32","dev":"en0"}
	]`)
	routes, err := parseLinuxRoutePrefixes(linuxJSON)
	if err != nil {
		t.Fatalf("parse Linux routes: %v", err)
	}
	if err := checkCandidateRoutes([]netip.Addr{netip.MustParseAddr("100.64.12.1")}, routes); err == nil {
		t.Fatal("expected candidate inside existing Linux route to be rejected")
	}
	if err := checkCandidateRoutes([]netip.Addr{netip.MustParseAddr("198.51.100.1")}, routes); err != nil {
		t.Fatalf("candidate covered only by default route rejected: %v", err)
	}

	for _, test := range []struct {
		destination string
		bits        int
	}{
		{destination: "10", bits: 8},
		{destination: "192.168.1", bits: 24},
		{destination: "192.168.1.7", bits: 32},
	} {
		prefix, skip, err := parseDarwinIPv4Prefix(test.destination)
		if err != nil || skip || prefix.Bits() != test.bits {
			t.Fatalf("parse Darwin %q = %s, skip=%v, err=%v; want /%d", test.destination, prefix, skip, err, test.bits)
		}
	}

	windowsSingle := []byte(`{"DestinationPrefix":"0.0.0.0/0"}`)
	routes, err = parseWindowsRoutePrefixes(windowsSingle)
	if err != nil {
		t.Fatalf("parse Windows default route: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("Windows default routes = %#v, want none", routes)
	}
}

func TestOpenWithPlanRollbackAndIdempotentCleanup(t *testing.T) {
	ctx := context.Background()
	runner := &recordingRunner{}
	device := &fakeDevice{name: "wc0"}
	cfg := Config{
		Name:  "wc0",
		Local: netip.MustParseAddr("100.64.0.1"),
		Peer:  netip.MustParseAddr("100.64.0.2"),
		MTU:   DefaultMTU,
	}

	gotDevice, cleanup, err := openWithPlan(ctx, cfg, func(string, int) (tun.Device, error) {
		return device, nil
	}, runner, func(r commandRunner, name string, _ Config) setupPlan {
		return setupPlan{steps: []setupStep{
			commandStep(r, "first", "configure", []string{name, "one"}, "rollback", []string{"one"}),
			commandStep(r, "second", "configure", []string{name, "two"}, "rollback", []string{"two"}),
		}}
	})
	if err != nil {
		t.Fatalf("openWithPlan() error = %v", err)
	}
	if gotDevice != device {
		t.Fatal("openWithPlan returned a different device")
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup() error = %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("second cleanup() error = %v", err)
	}
	if got := runner.calls(); !reflect.DeepEqual(got, []recordedCall{
		{name: "configure", args: []string{"wc0", "one"}},
		{name: "configure", args: []string{"wc0", "two"}},
		{name: "rollback", args: []string{"two"}},
		{name: "rollback", args: []string{"one"}},
	}) {
		t.Fatalf("commands = %#v", got)
	}
	if device.closeCount() != 1 {
		t.Fatalf("device close count = %d, want 1", device.closeCount())
	}
}

func TestOpenWithPlanFailureRollsBackSuccessfulSteps(t *testing.T) {
	runner := &recordingRunner{failAt: 2}
	device := &fakeDevice{name: "wc0"}
	cfg := Config{
		Name:  "wc0",
		Local: netip.MustParseAddr("100.64.0.1"),
		Peer:  netip.MustParseAddr("100.64.0.2"),
		MTU:   DefaultMTU,
	}

	gotDevice, cleanup, err := openWithPlan(context.Background(), cfg, func(string, int) (tun.Device, error) {
		return device, nil
	}, runner, func(r commandRunner, name string, _ Config) setupPlan {
		return setupPlan{steps: []setupStep{
			commandStep(r, "first", "configure", []string{name, "one"}, "rollback", []string{"one"}),
			commandStep(r, "second", "configure", []string{name, "two"}, "rollback", []string{"two"}),
		}}
	})
	if gotDevice != nil || cleanup != nil {
		t.Fatalf("failure returned device=%v cleanup=%v", gotDevice, cleanup != nil)
	}
	if err == nil || !strings.Contains(err.Error(), "second") {
		t.Fatalf("error = %v, want failed second step", err)
	}
	if got := runner.calls(); !reflect.DeepEqual(got, []recordedCall{
		{name: "configure", args: []string{"wc0", "one"}},
		{name: "configure", args: []string{"wc0", "two"}},
		{name: "rollback", args: []string{"one"}},
	}) {
		t.Fatalf("rollback commands = %#v", got)
	}
	if device.closeCount() != 1 {
		t.Fatalf("device close count = %d, want 1", device.closeCount())
	}
}

func TestCleanupIgnoresCanceledSetupContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &recordingRunner{}
	device := &fakeDevice{name: "wc0"}
	cfg := Config{
		Name:  "wc0",
		Local: netip.MustParseAddr("100.64.0.1"),
		Peer:  netip.MustParseAddr("100.64.0.2"),
		MTU:   DefaultMTU,
	}
	_, cleanup, err := openWithPlan(ctx, cfg, func(string, int) (tun.Device, error) {
		return device, nil
	}, runner, func(r commandRunner, name string, _ Config) setupPlan {
		return setupPlan{steps: []setupStep{
			commandStep(r, "first", "configure", []string{name}, "rollback", []string{name}),
		}}
	})
	if err != nil {
		t.Fatalf("openWithPlan() error = %v", err)
	}
	cancel()
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup after context cancellation: %v", err)
	}
}

func testInterfaceName() string {
	if runtime.GOOS == "darwin" {
		return "utun"
	}
	return "wc0"
}

type recordedCall struct {
	name string
	args []string
}

type recordingRunner struct {
	mu     sync.Mutex
	all    []recordedCall
	failAt int
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.all = append(r.all, recordedCall{name: name, args: append([]string(nil), args...)})
	if r.failAt > 0 && len(r.all) == r.failAt {
		return errors.New("recorded command failure")
	}
	return nil
}

func (r *recordingRunner) calls() []recordedCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedCall(nil), r.all...)
}

type fakeDevice struct {
	mu    sync.Mutex
	name  string
	close int
}

func (*fakeDevice) File() *os.File { return nil }

func (*fakeDevice) Read([][]byte, []int, int) (int, error) { return 0, errors.New("fake device read") }

func (*fakeDevice) Write([][]byte, int) (int, error) { return 0, errors.New("fake device write") }

func (*fakeDevice) MTU() (int, error) { return DefaultMTU, nil }

func (d *fakeDevice) Name() (string, error) { return d.name, nil }

func (*fakeDevice) Events() <-chan tun.Event { return nil }

func (d *fakeDevice) Close() error {
	d.mu.Lock()
	d.close++
	d.mu.Unlock()
	return nil
}

func (*fakeDevice) BatchSize() int { return 1 }

func (d *fakeDevice) closeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.close
}
