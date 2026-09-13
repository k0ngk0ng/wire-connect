//go:build integration && windows && amd64

package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/k0ngk0ng/wire-connect/internal/nethelper"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

const helperTestUtilityEnv = "WIRE_CONNECT_HELPER_TESTUTIL"

type windowsHelperTestReceipt struct {
	SID       string `json:"sid"`
	Elevated  bool   `json:"elevated"`
	Interface string `json:"interface"`
	Local     string `json:"local"`
	Peer      string `json:"peer"`
	Sent      bool   `json:"sent"`
	Received  bool   `json:"received"`
}

// TestRealNetworkHelperLifecycle exercises the Windows privilege split with
// the real named-pipe endpoint and Wintun adapter. The test process owns the
// elevated helper and its adapter; the separately built client runs with the
// linked, non-elevated UAC token and uses nethelper.Open over IPC.
//
// Set WIRE_CONNECT_NETWORK_TEST=1 and WIRE_CONNECT_HELPER_TESTUTIL to a
// separately built cmd/wire-connect-helper-testutil.exe. The test must run in
// an elevated Administrator process. It is intentionally never run by the
// ordinary local test command.
func TestRealNetworkHelperLifecycle(t *testing.T) {
	if os.Getenv("WIRE_CONNECT_NETWORK_TEST") != "1" {
		t.Skip("set WIRE_CONNECT_NETWORK_TEST=1 on an elevated Windows CI worker to run the real network helper test")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("WIRE_CONNECT_NETWORK_TEST=1 requires an elevated Administrator test process")
	}
	utility := windowsHelperTestUtility(t)
	linked, identity := windowsLimitedToken(t)
	defer linked.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := Check(ctx); err != nil {
		t.Fatalf("Windows platform prerequisites: %v", err)
	}
	local, peer, err := chooseNetworkTestPair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	name := networkTestInterfaceName()
	const mtu = DefaultMTU

	helperCtx, stopHelper := context.WithCancel(ctx)
	helperDone := make(chan error, 1)
	go func() {
		// The callback remains in this elevated test process, so platform.Open
		// takes the native Wintun path rather than recursing into nethelper.Open.
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
		if helperErr != nil && !errors.Is(helperErr, context.Canceled) {
			t.Errorf("privileged network helper: %v", helperErr)
		}
	}()

	args := []string{
		"--name", name,
		"--local", local.String(),
		"--peer", peer.String(),
		"--mtu", strconv.Itoa(mtu),
	}
	stdout, stderr, err := runWindowsLimitedProcess(ctx, linked, utility, args)
	if err != nil {
		t.Fatalf("unprivileged helper client: %v\nstdout: %s\nstderr: %s", err, strings.TrimSpace(stdout), strings.TrimSpace(stderr))
	}
	var receipt windowsHelperTestReceipt
	if err := json.Unmarshal(bytes.TrimSpace([]byte(stdout)), &receipt); err != nil {
		t.Fatalf("decode unprivileged helper receipt %q: %v\nstderr: %s", strings.TrimSpace(stdout), err, strings.TrimSpace(stderr))
	}
	if receipt.SID != identity || receipt.Elevated {
		t.Fatalf("helper client token = SID %q elevated=%v, want SID %q and non-elevated", receipt.SID, receipt.Elevated, identity)
	}
	if !receipt.Sent || !receipt.Received || receipt.Local != local.String() || receipt.Peer != peer.String() {
		t.Fatalf("unexpected helper client receipt: %#v", receipt)
	}
	if receipt.Interface == "" {
		t.Fatal("helper client did not report the real Wintun interface name")
	}

	// The proxy cleanup must close the privileged Wintun adapter and undo the
	// address/host route before the helper server is stopped.
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
}

func windowsHelperTestUtility(t *testing.T) string {
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
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		t.Fatalf("helper test utility %q is not a regular file", abs)
	}
	return filepath.Clean(abs)
}

func windowsLimitedToken(t *testing.T) (windows.Token, string) {
	t.Helper()
	current := windows.GetCurrentProcessToken()
	linked, err := current.GetLinkedToken()
	if err == nil {
		if linked.IsElevated() {
			linked.Close()
			t.Fatal("linked UAC token is still elevated")
		}
		return windowsTokenIdentity(t, linked)
	}

	// Hosted Windows runners may have UAC disabled and consequently expose no
	// linked token. Create a primary restricted token in that case instead of
	// weakening this test to an elevated child. Disable the Administrators SID
	// as well as every privilege so the child is unambiguously non-elevated.
	restricted, restrictedErr := createRestrictedToken()
	if restrictedErr != nil {
		t.Fatalf("get a non-elevated UAC token (%v) and create a restricted token: %v", err, restrictedErr)
	}
	if restricted.IsElevated() {
		restricted.Close()
		t.Fatalf("restricted child token is still elevated (linked token error: %v)", err)
	}
	return windowsTokenIdentity(t, restricted)
}

func windowsTokenIdentity(t *testing.T, token windows.Token) (windows.Token, string) {
	t.Helper()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		token.Close()
		t.Fatalf("read non-elevated child token SID: %v", err)
	}
	return token, user.User.Sid.String()
}

const disableMaxPrivilege = 0x1

var advapi32 = windows.NewLazySystemDLL("advapi32.dll")

func createRestrictedToken() (windows.Token, error) {
	// GetCurrentProcessToken returns a pseudo handle. Open a real token with
	// the access CreateRestrictedToken requires; this also works on systems
	// where UAC is disabled and TokenLinkedToken is unavailable.
	var source windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_QUERY | windows.TOKEN_ADJUST_DEFAULT | windows.TOKEN_ADJUST_GROUPS | windows.TOKEN_ADJUST_PRIVILEGES)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &source); err != nil {
		return 0, fmt.Errorf("open current process token: %w", err)
	}
	defer source.Close()
	var admins *windows.SID
	var err error
	admins, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, fmt.Errorf("create Administrators SID: %w", err)
	}
	disable := windows.SIDAndAttributes{Sid: admins}
	var restricted windows.Token
	proc := advapi32.NewProc("CreateRestrictedToken")
	r, _, callErr := proc.Call(
		uintptr(source),
		uintptr(disableMaxPrivilege),
		uintptr(1),
		uintptr(unsafe.Pointer(&disable)),
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&restricted)),
	)
	if r == 0 {
		if callErr == nil {
			callErr = windows.GetLastError()
		}
		return 0, fmt.Errorf("CreateRestrictedToken: %w", callErr)
	}
	return restricted, nil
}

func runWindowsLimitedProcess(ctx context.Context, token windows.Token, path string, args []string) (stdout, stderr string, err error) {
	cmd := exec.CommandContext(ctx, path, args...)
	// os/exec uses CreateProcessAsUser when SysProcAttr.Token is set. Using the
	// linked token here is essential: merely launching from an elevated parent
	// would cause nethelper.currentSID/trusted peer checks to observe the admin
	// token and would not test the named-pipe ACL boundary.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:      syscall.Token(token),
		HideWindow: true,
	}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}
