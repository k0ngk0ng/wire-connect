//go:build integration && ((linux && (amd64 || arm64)) || (darwin && (amd64 || arm64)) || (windows && amd64))

package platform

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestOpenRealTUNLifecycle is intentionally opt-in.  It changes host network
// state for the duration of the test and should only run on a privileged CI
// worker with the platform prerequisites and (on Windows) wintun.dll beside
// the test executable.
func TestOpenRealTUNLifecycle(t *testing.T) {
	if os.Getenv("WIRE_CONNECT_NETWORK_TEST") != "1" {
		t.Skip("set WIRE_CONNECT_NETWORK_TEST=1 on a privileged CI worker to run the real TUN test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := Check(ctx); err != nil {
		t.Fatalf("platform prerequisites: %v", err)
	}

	local, peer, err := chooseNetworkTestPair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	name := networkTestInterfaceName()
	device, cleanup, err := Open(ctx, Config{Name: name, Local: local, Peer: peer, MTU: DefaultMTU})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	actualName, err := device.Name()
	if err != nil {
		_ = cleanup()
		t.Fatalf("read created TUN name: %v", err)
	}
	defer func() { _ = cleanup() }()

	if err := Available(ctx, peer); err == nil || !strings.Contains(err.Error(), "overlaps existing route") {
		t.Fatalf("peer route was not observed after Open: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("second cleanup: %v", err)
	}
	if err := waitForInterfaceGone(ctx, actualName); err != nil {
		t.Fatal(err)
	}
	if err := Available(ctx, local, peer); err != nil {
		t.Fatalf("addresses/routes remained after cleanup: %v", err)
	}
}

func chooseNetworkTestPair(ctx context.Context) (netip.Addr, netip.Addr, error) {
	for subnet := byte(1); subnet < 250; subnet++ {
		local := netip.AddrFrom4([4]byte{100, 64, subnet, 1})
		peer := netip.AddrFrom4([4]byte{100, 64, subnet, 2})
		if err := Available(ctx, local, peer); err == nil {
			return local, peer, nil
		} else if !strings.Contains(err.Error(), "overlaps existing route") {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("choose test addresses: %w", err)
		}
	}
	return netip.Addr{}, netip.Addr{}, errors.New("no unused 100.64/10 test address pair is available")
}

func networkTestInterfaceName() string {
	if runtime.GOOS == "darwin" {
		return "utun"
	}
	return "wct" + strconv.Itoa(os.Getpid()%100000000)
}

func waitForInterfaceGone(ctx context.Context, name string) error {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ensureInterfaceAbsent(name); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("interface %q did not disappear: %w", name, ctx.Err())
		case <-deadline.C:
			return fmt.Errorf("interface %q did not disappear after cleanup", name)
		case <-tick.C:
		}
	}
}
