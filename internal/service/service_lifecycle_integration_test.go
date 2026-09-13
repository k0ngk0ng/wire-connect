//go:build (linux && (amd64 || arm64)) || (darwin && (amd64 || arm64)) || (windows && amd64)

package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/localctl"
)

const (
	serviceIntegrationEnv    = "WIRE_CONNECT_SERVICE_INTEGRATION"
	serviceIntegrationHelper = "WIRE_CONNECT_SERVICE_HELPER"
	serviceIntegrationRoot   = "WIRE_CONNECT_SERVICE_STATE_ROOT"
)

type integrationServiceStatus struct {
	Name     string `json:"name"`
	StateDir string `json:"state_dir"`
	PairID   string `json:"pair_id"`
	PID      int    `json:"pid"`
}

type integrationServiceReceipt struct {
	Event    string `json:"event"`
	Name     string `json:"name"`
	StateDir string `json:"state_dir"`
	PairID   string `json:"pair_id"`
	PID      int    `json:"pid"`
}

// TestRealServiceLifecycle is intentionally opt-in. It installs a unique
// native service, starts the independent test helper through the real service
// manager, observes the helper through localctl, then stops and uninstalls it.
// The helper reads a config.Profile before serving status, so the test covers
// the state directory and profile-name identity shared by config and localctl.
//
// Set WIRE_CONNECT_SERVICE_INTEGRATION=1 and
// WIRE_CONNECT_SERVICE_HELPER to a separately built
// cmd/wire-connect-service-testutil binary. The test process must be root on
// Unix and elevated Administrator on Windows. On Windows the helper directory
// must also contain the official x64 wintun.dll because the production
// installer validates the adjacent runtime even though this helper never opens
// a TUN device.
func TestRealServiceLifecycle(t *testing.T) {
	if os.Getenv(serviceIntegrationEnv) != "1" {
		t.Skip("set WIRE_CONNECT_SERVICE_INTEGRATION=1 to run the native service lifecycle test")
	}
	helper := integrationHelper(t)
	if runtime.GOOS == "windows" {
		if _, err := os.Lstat(filepath.Join(filepath.Dir(helper), "wintun.dll")); err != nil {
			t.Fatalf("official x64 wintun.dll beside service helper is required: %v", err)
		}
	}

	name := integrationServiceName(t)
	stateDir := integrationStateDir(t, name)
	store := config.Store{Dir: stateDir}
	cleanupIntegrationService(t, name, stateDir)
	if err := store.Init(); err != nil {
		t.Fatalf("initialize integration state directory: %v", err)
	}
	pairID := "service-test-" + name
	profile := config.Profile{
		Server:    "service-lifecycle-test",
		PairID:    pairID,
		Host:      true,
		Secret:    []byte("test-only-profile-secret"),
		LocalIP:   "100.64.0.1",
		PeerIP:    "100.64.0.2",
		Interface: "service-test",
		MTU:       1420,
	}
	if err := store.Write("profile-"+name, profile); err != nil {
		t.Fatalf("write integration profile: %v", err)
	}

	cfg := Config{Executable: helper, StateDir: stateDir, Name: name}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := Install(ctx, cfg); err != nil {
		t.Fatalf("install native service: %v", err)
	}
	firstReceipt, err := waitIntegrationReceipt(ctx, store, name, "service-receipt-", "started", stateDir, pairID)
	if err != nil {
		t.Fatalf("wait for service startup receipt: %v", err)
	}
	firstStatus, err := waitIntegrationReady(ctx, stateDir, name, pairID)
	if err != nil {
		t.Fatalf("wait for service helper: %v", err)
	}
	if firstReceipt.PID != firstStatus.PID {
		t.Fatalf("startup receipt PID %d differs from local status PID %d", firstReceipt.PID, firstStatus.PID)
	}
	if err := waitIntegrationServiceState(ctx, name, true); err != nil {
		t.Fatalf("wait for native service running: %v", err)
	}

	// Stop through localctl first. On Windows this crosses the Administrator to
	// LocalSystem named-pipe ACL boundary; the receipt proves that the service
	// process accepted the request and used the same config identity.
	if err := localctl.Stop(ctx, stateDir, name); err != nil {
		t.Fatalf("stop through local control: %v", err)
	}
	if _, err := waitIntegrationReceipt(ctx, store, name, "service-stop-", "local-stop", stateDir, pairID); err != nil {
		t.Fatalf("wait for local stop receipt: %v", err)
	}

	// Disable the first run after localctl.Stop. This also prevents launchd's
	// KeepAlive policy from immediately starting another helper before the
	// second run below.
	if err := Stop(ctx, name); err != nil {
		t.Fatalf("disable service after local stop: %v", err)
	}
	if err := waitIntegrationEndpointGone(ctx, stateDir, name); err != nil {
		t.Fatalf("wait for local control cleanup: %v", err)
	}
	if err := waitIntegrationServiceState(ctx, name, false); err != nil {
		t.Fatalf("wait for native service stopped after local stop: %v", err)
	}

	// Install again and stop through the native manager while the helper is
	// still running. This exercises Windows service.Run's SCM stop response;
	// Unix service managers deliver the corresponding termination signal.
	if err := Install(ctx, cfg); err != nil {
		t.Fatalf("reinstall native service: %v", err)
	}
	secondStatus, err := waitIntegrationReady(ctx, stateDir, name, pairID)
	if err != nil {
		t.Fatalf("wait for service helper restart: %v", err)
	}
	if secondStatus.PID == firstStatus.PID {
		t.Fatalf("service reinstall reused first helper PID %d", firstStatus.PID)
	}
	secondReceipt, err := waitIntegrationReceipt(ctx, store, name, "service-receipt-", "started", stateDir, pairID)
	if err != nil {
		t.Fatalf("wait for service restart receipt: %v", err)
	}
	if secondReceipt.PID != secondStatus.PID {
		t.Fatalf("restart receipt PID %d differs from local status PID %d", secondReceipt.PID, secondStatus.PID)
	}
	if err := waitIntegrationServiceState(ctx, name, true); err != nil {
		t.Fatalf("wait for native service restart: %v", err)
	}
	if err := Stop(ctx, name); err != nil {
		t.Fatalf("stop native service through manager: %v", err)
	}
	if err := waitIntegrationEndpointGone(ctx, stateDir, name); err != nil {
		t.Fatalf("wait for local control cleanup after manager stop: %v", err)
	}
	if err := waitIntegrationServiceState(ctx, name, false); err != nil {
		t.Fatalf("wait for native service stopped after manager stop: %v", err)
	}

	if err := Uninstall(ctx, name); err != nil {
		t.Fatalf("uninstall native service: %v", err)
	}
	if installed, err := integrationInstalledArtifacts(name); err != nil {
		t.Fatalf("inspect installed service artifacts: %v", err)
	} else if installed {
		t.Fatal("uninstall left package-owned service artifacts")
	}
	var retained config.Profile
	if err := store.Read("profile-"+name, &retained); err != nil {
		t.Fatalf("uninstall removed retained profile: %v", err)
	}
	if retained.PairID != pairID {
		t.Fatalf("retained profile PairID = %q; want %q", retained.PairID, pairID)
	}
}

func integrationHelper(t *testing.T) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(serviceIntegrationHelper))
	if path == "" {
		t.Fatal("WIRE_CONNECT_SERVICE_HELPER must point to the separately built service test helper")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve service helper: %v", err)
	}
	st, err := os.Lstat(abs)
	if err != nil {
		t.Fatalf("inspect service helper %q: %v", abs, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		t.Fatalf("service helper %q is not a regular file", abs)
	}
	return filepath.Clean(abs)
}

func integrationStateDir(t *testing.T, name string) string {
	t.Helper()
	base := strings.TrimSpace(os.Getenv(serviceIntegrationRoot))
	if base == "" {
		repo := integrationRepoRoot(t)
		base = filepath.Join(repo, ".cache", "svc")
	}
	base, err := filepath.Abs(base)
	if err != nil {
		t.Fatalf("resolve service state root: %v", err)
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatalf("create service state root: %v", err)
	}
	// Store.Init creates and protects the final directory. Avoid MkdirTemp,
	// whose pre-created directory would inherit a broad Windows ACL and would
	// therefore be rejected by the production state-directory validation.
	return filepath.Join(base, name)
}

func integrationRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get test working directory: %v", err)
	}
	for {
		if st, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && st.Mode().IsRegular() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate repository go.mod")
	return ""
}

func integrationServiceName(t *testing.T) string {
	t.Helper()
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("generate service integration name: %v", err)
	}
	return "it" + hex.EncodeToString(suffix[:])
}

func cleanupIntegrationService(t *testing.T, name, stateDir string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		_ = Stop(ctx, name)
		_ = Uninstall(ctx, name)
		_ = os.RemoveAll(stateDir)
	})
}

func waitIntegrationReady(ctx context.Context, dir, name, pairID string) (integrationServiceStatus, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var got integrationServiceStatus
		if err := localctl.Status(ctx, dir, name, &got); err == nil {
			if got.Name != name || got.StateDir != dir || got.PairID != pairID || got.PID <= 0 {
				return integrationServiceStatus{}, fmt.Errorf("unexpected local status: %#v", got)
			}
			return got, nil
		}
		select {
		case <-ctx.Done():
			return integrationServiceStatus{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func waitIntegrationReceipt(ctx context.Context, store config.Store, name, keyPrefix, event, stateDir, pairID string) (integrationServiceReceipt, error) {
	key := keyPrefix + name
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var receipt integrationServiceReceipt
		if err := store.Read(key, &receipt); err == nil {
			if receipt.Event != event || receipt.Name != name || receipt.StateDir != stateDir || receipt.PairID != pairID || receipt.PID <= 0 {
				return integrationServiceReceipt{}, fmt.Errorf("unexpected %s receipt: %#v", key, receipt)
			}
			return receipt, nil
		}
		select {
		case <-ctx.Done():
			return integrationServiceReceipt{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func waitIntegrationEndpointGone(ctx context.Context, dir, name string) error {
	for {
		requestCtx, cancel := context.WithTimeout(ctx, time.Second)
		var status integrationServiceStatus
		err := localctl.Status(requestCtx, dir, name, &status)
		cancel()
		if err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func waitIntegrationServiceState(ctx context.Context, name string, running bool) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := Status(ctx, name)
		if err == nil {
			if running && integrationRunningState(state) {
				return nil
			}
			if !running && integrationStoppedState(state) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return fmt.Errorf("last status error: %w", err)
			}
			return fmt.Errorf("last service state %q did not reach desired state", state)
		case <-ticker.C:
		}
	}
}

func integrationRunningState(state string) bool {
	return state == "active" || state == "running" || state == "loaded"
}

func integrationStoppedState(state string) bool {
	return state == "inactive" || state == "stopped" || state == "exited"
}
