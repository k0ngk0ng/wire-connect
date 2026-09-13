//go:build (linux && (amd64 || arm64)) || (darwin && (amd64 || arm64)) || (windows && amd64)

package service

import (
	"context"
	"errors"
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
	userServiceIntegrationEnv      = "WIRE_CONNECT_USER_SERVICE_INTEGRATION"
	userServiceIntegrationRequired = "WIRE_CONNECT_USER_SERVICE_REQUIRED"
	userServiceIntegrationHelper   = "WIRE_CONNECT_USER_SERVICE_HELPER"
	userServiceIntegrationRoot     = "WIRE_CONNECT_USER_SERVICE_STATE_ROOT"
)

// TestRealUserServiceLifecycle is opt-in because it registers a real service
// in the current user's launchd/systemd/Task Scheduler namespace. It never
// requires elevation and does not create a TUN; the helper only exercises the
// local control endpoint and saved profile identity.
func TestRealUserServiceLifecycle(t *testing.T) {
	if os.Getenv(userServiceIntegrationEnv) != "1" {
		t.Skip("set WIRE_CONNECT_USER_SERVICE_INTEGRATION=1 to run the current-user service lifecycle test")
	}
	helper := userServiceIntegrationHelperPath(t)
	if runtime.GOOS == "windows" {
		if _, err := os.Lstat(filepath.Join(filepath.Dir(helper), "wintun.dll")); err != nil {
			t.Fatalf("official x64 wintun.dll beside user service helper is required: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := UserCheck(ctx); err != nil {
		if os.Getenv(userServiceIntegrationRequired) == "1" {
			t.Fatalf("current-user service manager is unavailable: %v", err)
		}
		t.Skipf("current-user service manager is unavailable: %v", err)
	}

	name := integrationServiceName(t)
	stateDir := userIntegrationStateDir(t, name)
	store := config.Store{Dir: stateDir}
	cleanupUserIntegrationService(t, name, stateDir)
	if err := store.Init(); err != nil {
		t.Fatalf("initialize user integration state directory: %v", err)
	}
	pairID := "user-service-test-" + name
	profile := config.Profile{
		Server:    "user-service-lifecycle-test",
		PairID:    pairID,
		Host:      true,
		Secret:    []byte("test-only-profile-secret"),
		LocalIP:   "100.64.0.1",
		PeerIP:    "100.64.0.2",
		Interface: "user-service-test",
		MTU:       1420,
	}
	if err := store.Write("profile-"+name, profile); err != nil {
		t.Fatalf("write user integration profile: %v", err)
	}

	cfg := Config{Executable: helper, StateDir: stateDir, Name: name}
	if err := UserInstall(ctx, cfg); err != nil {
		t.Fatalf("install current-user service: %v", err)
	}
	firstReceipt, err := waitIntegrationReceipt(ctx, store, name, "service-receipt-", "started", stateDir, pairID)
	if err != nil {
		t.Fatalf("wait for user service startup receipt: %v", err)
	}
	firstStatus, err := waitIntegrationReady(ctx, stateDir, name, pairID)
	if err != nil {
		t.Fatalf("wait for user service helper: %v", err)
	}
	if firstReceipt.PID != firstStatus.PID {
		t.Fatalf("user service startup receipt PID %d differs from local status PID %d", firstReceipt.PID, firstStatus.PID)
	}
	if err := waitUserServiceState(ctx, name, true); err != nil {
		t.Fatalf("wait for user service running: %v", err)
	}

	if err := localctl.Stop(ctx, stateDir, name); err != nil {
		t.Fatalf("stop user service through local control: %v", err)
	}
	if _, err := waitIntegrationReceipt(ctx, store, name, "service-stop-", "local-stop", stateDir, pairID); err != nil {
		t.Fatalf("wait for user service local stop receipt: %v", err)
	}
	if err := UserStop(ctx, name); err != nil {
		t.Fatalf("disable current-user service: %v", err)
	}
	if err := waitIntegrationEndpointGone(ctx, stateDir, name); err != nil {
		t.Fatalf("wait for user service local control cleanup: %v", err)
	}
	if err := waitUserServiceState(ctx, name, false); err != nil {
		t.Fatalf("wait for user service stopped after disable: %v", err)
	}

	if err := UserInstall(ctx, cfg); err != nil {
		t.Fatalf("reinstall current-user service: %v", err)
	}
	secondStatus, err := waitIntegrationReady(ctx, stateDir, name, pairID)
	if err != nil {
		t.Fatalf("wait for user service restart: %v", err)
	}
	if secondStatus.PID == firstStatus.PID {
		t.Fatalf("user service reinstall reused first helper PID %d", firstStatus.PID)
	}
	if err := UserStop(ctx, name); err != nil {
		t.Fatalf("stop current-user service through manager: %v", err)
	}
	if err := waitIntegrationEndpointGone(ctx, stateDir, name); err != nil {
		t.Fatalf("wait for user service cleanup after manager stop: %v", err)
	}
	if err := waitUserServiceState(ctx, name, false); err != nil {
		t.Fatalf("wait for user service stopped after manager stop: %v", err)
	}

	if err := UserUninstall(ctx, name); err != nil {
		t.Fatalf("uninstall current-user service: %v", err)
	}
	if _, err := UserStatus(ctx, name); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("UserStatus after uninstall = %v; want ErrNotInstalled", err)
	}
	var retained config.Profile
	if err := store.Read("profile-"+name, &retained); err != nil {
		t.Fatalf("user service uninstall removed retained profile: %v", err)
	}
	if retained.PairID != pairID {
		t.Fatalf("retained profile PairID = %q; want %q", retained.PairID, pairID)
	}
}

func userServiceIntegrationHelperPath(t *testing.T) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(userServiceIntegrationHelper))
	if path == "" {
		t.Fatal("WIRE_CONNECT_USER_SERVICE_HELPER must point to the separately built user service test helper")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve user service helper: %v", err)
	}
	st, err := os.Lstat(abs)
	if err != nil {
		t.Fatalf("inspect user service helper %q: %v", abs, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		t.Fatalf("user service helper %q is not a regular file", abs)
	}
	return filepath.Clean(abs)
}

func userIntegrationStateDir(t *testing.T, name string) string {
	t.Helper()
	base := strings.TrimSpace(os.Getenv(userServiceIntegrationRoot))
	if base == "" {
		base = filepath.Join(integrationRepoRoot(t), ".cache", "user-svc")
	}
	base, err := filepath.Abs(base)
	if err != nil {
		t.Fatalf("resolve user service state root: %v", err)
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatalf("create user service state root: %v", err)
	}
	return filepath.Join(base, name)
}

func cleanupUserIntegrationService(t *testing.T, name, stateDir string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		_ = UserStop(ctx, name)
		_ = UserUninstall(ctx, name)
		_ = os.RemoveAll(stateDir)
	})
}

func waitUserServiceState(ctx context.Context, name string, running bool) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var last string
	for {
		state, err := UserStatus(ctx, name)
		if err == nil {
			last = state
			if running && integrationRunningState(state) {
				return nil
			}
			if !running && integrationStoppedState(state) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			if last != "" {
				return fmt.Errorf("last user service state %q did not reach desired state: %w", last, ctx.Err())
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
