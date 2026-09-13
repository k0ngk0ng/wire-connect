//go:build integration && ((linux && (amd64 || arm64)) || (darwin && (amd64 || arm64)))

package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/nethelper"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	helperTestUtilityEnv = "WIRE_CONNECT_HELPER_TESTUTIL"
	helperSocketDir      = "/var/run/wire-connect-nethelper"
)

type helperTestReceipt struct {
	UID       int    `json:"uid"`
	Interface string `json:"interface"`
	Local     string `json:"local"`
	Peer      string `json:"peer"`
	Sent      bool   `json:"sent"`
	Received  bool   `json:"received"`
}

// TestRealNetworkHelperLifecycle exercises the full Unix privilege split:
// the root test process owns the real TUN and its network configuration while
// a separately built, credential-dropped child sends and receives packets
// through nethelper's unprivileged proxy. It is deliberately opt-in because it
// changes host network state for the duration of the test.
//
// Set WIRE_CONNECT_NETWORK_TEST=1 and WIRE_CONNECT_HELPER_TESTUTIL to a
// separately built cmd/wire-connect-helper-testutil binary. The test process
// must be root. No local run should use this test unless it is an explicitly
// provisioned disposable test environment.
func TestRealNetworkHelperLifecycle(t *testing.T) {
	if os.Getenv("WIRE_CONNECT_NETWORK_TEST") != "1" {
		t.Skip("set WIRE_CONNECT_NETWORK_TEST=1 on a privileged CI worker to run the real network helper test")
	}
	if os.Geteuid() != 0 {
		t.Skip("the real network helper test requires a root test process")
	}
	utility := helperTestUtility(t)
	uid, gid := helperTestIdentity(t)
	identity := strconv.FormatUint(uint64(uid), 10)
	socketPath := helperTestSocketPath(identity)
	if _, err := os.Lstat(socketPath); err == nil {
		t.Fatalf("network helper endpoint %q already exists; refusing to interfere with another helper", socketPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect network helper endpoint %q: %v", socketPath, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	local, peer, err := chooseNetworkTestPair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	name := networkTestInterfaceName()
	const mtu = DefaultMTU

	helperCtx, stopHelper := context.WithCancel(ctx)
	helperDone := make(chan error, 1)
	go func() {
		// This callback runs in the root test process. Open sees native root
		// privileges here and therefore cannot recurse into nethelper.Open.
		helperDone <- nethelper.Serve(helperCtx, identity, func(openCtx context.Context, c nethelper.Config) (tun.Device, func() error, error) {
			localAddr, err := netip.ParseAddr(c.Local)
			if err != nil {
				return nil, nil, err
			}
			peerAddr, err := netip.ParseAddr(c.Peer)
			if err != nil {
				return nil, nil, err
			}
			return Open(openCtx, Config{Name: c.Name, Local: localAddr, Peer: peerAddr, MTU: c.MTU})
		})
	}()

	var helperErr error
	defer func() {
		stopHelper()
		if helperErr == nil {
			select {
			case helperErr = <-helperDone:
			case <-time.After(5 * time.Second):
				t.Errorf("privileged network helper did not stop")
			}
		}
		if helperErr != nil && !errors.Is(helperErr, context.Canceled) && !errors.Is(helperErr, nethelper.ErrUnavailable) {
			t.Errorf("privileged network helper: %v", helperErr)
		}
	}()

	args := []string{
		"--name", name,
		"--local", local.String(),
		"--peer", peer.String(),
		"--mtu", strconv.Itoa(mtu),
	}
	cmd := exec.CommandContext(ctx, utility, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("unprivileged helper client: %v\nstdout: %s\nstderr: %s", err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
	}
	var receipt helperTestReceipt
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &receipt); err != nil {
		t.Fatalf("decode unprivileged helper receipt %q: %v\nstderr: %s", strings.TrimSpace(stdout.String()), err, strings.TrimSpace(stderr.String()))
	}
	if receipt.UID == 0 || uint32(receipt.UID) != uid {
		t.Fatalf("helper client uid = %d, want dropped uid %d", receipt.UID, uid)
	}
	if !receipt.Sent || !receipt.Received || receipt.Local != local.String() || receipt.Peer != peer.String() {
		t.Fatalf("unexpected helper client receipt: %#v", receipt)
	}
	if receipt.Interface == "" {
		t.Fatal("helper client did not report the real TUN interface name")
	}

	// The child closes its proxy before exiting. That must tear down the
	// privileged TUN and route; wait for the actual dynamic utun name on macOS
	// as well as the requested Linux name.
	if err := waitForInterfaceGone(ctx, receipt.Interface); err != nil {
		t.Fatal(err)
	}
	if err := Available(ctx, local, peer); err != nil {
		t.Fatalf("addresses or routes remained after helper client cleanup: %v", err)
	}

	stopHelper()
	select {
	case helperErr = <-helperDone:
	case <-time.After(5 * time.Second):
		t.Fatal("privileged network helper did not stop")
	}
	if helperErr != nil && !errors.Is(helperErr, context.Canceled) {
		t.Fatalf("privileged network helper returned %v", helperErr)
	}
	if err := waitForHelperSocketGone(ctx, socketPath); err != nil {
		t.Fatal(err)
	}
}

func helperTestUtility(t *testing.T) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(helperTestUtilityEnv))
	if path == "" {
		t.Fatal("WIRE_CONNECT_HELPER_TESTUTIL must point to the separately built helper test utility")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve helper test utility: %v", err)
	}
	st, err := os.Lstat(abs)
	if err != nil {
		t.Fatalf("inspect helper test utility %q: %v", abs, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode()&0111 == 0 {
		t.Fatalf("helper test utility %q is not an executable regular file", abs)
	}
	return filepath.Clean(abs)
}

func helperTestIdentity(t *testing.T) (uid, gid uint32) {
	t.Helper()
	uidText := strings.TrimSpace(os.Getenv("SUDO_UID"))
	gidText := strings.TrimSpace(os.Getenv("SUDO_GID"))
	var account *user.User
	if uidText == "" {
		var err error
		account, err = user.Lookup("nobody")
		if err != nil {
			t.Fatalf("lookup fallback nobody account: %v", err)
		}
		uidText = account.Uid
		if gidText == "" {
			gidText = account.Gid
		}
	}
	parsedUID, err := strconv.ParseUint(uidText, 10, 32)
	if err != nil || parsedUID == 0 {
		t.Fatalf("SUDO_UID must identify a non-root user, got %q", uidText)
	}
	if account == nil {
		account, err = user.LookupId(uidText)
		if err != nil {
			t.Fatalf("lookup SUDO_UID %q: %v", uidText, err)
		}
	}
	if gidText == "" {
		gidText = account.Gid
	}
	parsedGID, err := strconv.ParseUint(gidText, 10, 32)
	if err != nil {
		t.Fatalf("SUDO_GID must be a decimal group ID, got %q", gidText)
	}
	return uint32(parsedUID), uint32(parsedGID)
}

func helperTestSocketPath(identity string) string {
	hash := sha256.Sum256([]byte(identity))
	return filepath.Join(helperSocketDir, fmt.Sprintf("%x.sock", hash[:12]))
}

func waitForHelperSocketGone(ctx context.Context, path string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect helper endpoint after cleanup: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("helper endpoint %q remained after cleanup: %w", path, ctx.Err())
		case <-ticker.C:
		}
	}
}
