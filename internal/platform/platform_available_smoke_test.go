//go:build (linux && (amd64 || arm64)) || (darwin && (amd64 || arm64)) || (windows && amd64)

package platform

import (
	"context"
	"net/netip"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

// TestAvailableReadOnlySmoke exercises the real platform route reader.  It
// does not call Check or Open and therefore needs no root/administrator
// privileges and cannot change network state.  A minimal developer image may
// omit one of the platform route tools; in that case the smoke test is
// skipped, while the CI images are expected to provide it.
func TestAvailableReadOnlySmoke(t *testing.T) {
	command := ""
	switch runtime.GOOS {
	case "linux":
		command = "ip"
	case "darwin":
		command = "netstat"
	case "windows":
		command = "powershell.exe"
	}
	if _, err := exec.LookPath(command); err != nil {
		t.Skipf("%s is unavailable in this environment: %v", command, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Available(ctx, netip.MustParseAddr("198.51.100.10")); err != nil {
		t.Fatalf("read-only route availability check: %v", err)
	}
}
