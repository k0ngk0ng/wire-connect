//go:build integration && windows && amd64

package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
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
// elevated helper and its adapter; the separately built client runs with a
// non-elevated token and uses nethelper.Open over IPC.
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
	linked, identity, cleanupIdentity := windowsLimitedToken(t)
	defer func() {
		_ = linked.Close()
		if cleanupIdentity != nil {
			if err := cleanupIdentity(); err != nil {
				t.Errorf("remove temporary Windows test account: %v", err)
			}
		}
	}()
	utility = stageWindowsHelperTestUtility(t, utility, identity)

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

func windowsLimitedToken(t *testing.T) (windows.Token, string, func() error) {
	t.Helper()
	current := windows.GetCurrentProcessToken()
	linked, err := current.GetLinkedToken()
	if err == nil {
		if linked.IsElevated() {
			linked.Close()
		} else {
			return windowsTokenIdentity(t, linked)
		}
	}

	// Hosted Windows runners may have UAC disabled and consequently expose no
	// usable linked token. Create an actual standard local account in that case
	// instead of weakening this test to an elevated or restricted child.
	account, accountErr := newTemporaryWindowsAccount()
	if accountErr != nil {
		t.Fatalf("get a non-elevated UAC token (%v) and create a temporary standard account: %v", err, accountErr)
	}
	token, loginErr := account.login()
	if loginErr != nil {
		_ = account.remove()
		t.Fatalf("log on to temporary standard account: %v", loginErr)
	}
	if token.IsElevated() {
		_ = token.Close()
		_ = account.remove()
		t.Fatal("temporary standard account token is elevated")
	}
	sid, sidErr := tokenSID(token)
	if sidErr != nil {
		_ = token.Close()
		_ = account.remove()
		t.Fatalf("read temporary standard account SID: %v", sidErr)
	}
	return token, sid, account.remove
}

func windowsTokenIdentity(t *testing.T, token windows.Token) (windows.Token, string, func() error) {
	t.Helper()
	sid, err := tokenSID(token)
	if err != nil {
		token.Close()
		t.Fatalf("read non-elevated child token SID: %v", err)
	}
	return token, sid, nil
}

func tokenSID(token windows.Token) (string, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	if user == nil || user.User.Sid == nil {
		return "", errors.New("token has no user SID")
	}
	return user.User.Sid.String(), nil
}

func stageWindowsHelperTestUtility(t *testing.T, source, userSID string) string {
	t.Helper()
	windowsDir, err := windows.GetWindowsDirectory()
	if err != nil {
		t.Fatalf("locate Windows directory for standard-user test staging: %v", err)
	}
	root := filepath.Join(windowsDir, "Temp")
	dir, err := os.MkdirTemp(root, "wire-connect-helper-")
	if err != nil {
		t.Fatalf("create standard-user-readable helper staging directory: %v", err)
	}
	destination := filepath.Join(dir, "wire-connect-helper-testutil.exe")
	data, err := os.ReadFile(source)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("read helper test utility for staging: %v", err)
	}
	if err := os.WriteFile(destination, data, 0755); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("stage helper test utility for standard user: %v", err)
	}
	if err := setWindowsHelperTestACL(dir, destination, userSID); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("protect staged helper test utility from standard-user writes: %v", err)
	}
	t.Cleanup(func() {
		// Restore a writable DACL before removal in case cleanup runs under a
		// token that is not a member of the Administrators group.
		_ = setWindowsHelperTestACL(dir, destination, "")
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove helper staging directory: %v", err)
		}
	})
	return destination
}

func setWindowsHelperTestACL(directory, file, userSID string) error {
	if userSID == "" {
		// Cleanup is normally still elevated, so the original inherited ACL is
		// sufficient after the explicit test ACL has been removed by replacing it
		// with an administrator-owned protected descriptor.
		userSID = "BA"
	}
	directorySDDL := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;" + userSID + ")"
	fileSDDL := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;" + userSID + ")"
	if err := setWindowsHelperObjectACL(directory, directorySDDL); err != nil {
		return fmt.Errorf("set staging directory ACL: %w", err)
	}
	if err := setWindowsHelperObjectACL(file, fileSDDL); err != nil {
		return fmt.Errorf("set staged helper file ACL: %w", err)
	}
	return nil
}

func setWindowsHelperObjectACL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

type temporaryWindowsAccount struct {
	name     string
	password string
}

type windowsUserInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

const (
	userPrivUser                   = 1
	userFlagScript                 = 0x0001
	logon32LogonInteractive        = 2
	logon32ProviderDefault         = 0
	nerrUserExists          uint32 = 2224
	nerrUserNotFound        uint32 = 2221
)

var (
	netapi32 = windows.NewLazySystemDLL("netapi32.dll")
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
)

func newTemporaryWindowsAccount() (*temporaryWindowsAccount, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var randomName [4]byte
		if _, err := rand.Read(randomName[:]); err != nil {
			return nil, fmt.Errorf("generate temporary account name: %w", err)
		}
		name := "wct" + fmt.Sprintf("%x", randomName[:])
		var randomPassword [24]byte
		if _, err := rand.Read(randomPassword[:]); err != nil {
			return nil, fmt.Errorf("generate temporary account password: %w", err)
		}
		password := base64.RawURLEncoding.EncodeToString(randomPassword[:]) + "aA1!"
		name16, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, fmt.Errorf("encode temporary account name: %w", err)
		}
		password16, err := windows.UTF16PtrFromString(password)
		if err != nil {
			return nil, fmt.Errorf("encode temporary account password: %w", err)
		}
		info := windowsUserInfo1{Name: name16, Password: password16, Priv: userPrivUser, Flags: userFlagScript}
		code, err := netUserAdd(&info)
		if err != nil {
			if code == nerrUserExists {
				continue
			}
			return nil, fmt.Errorf("NetUserAdd temporary standard account: %w", err)
		}
		return &temporaryWindowsAccount{name: name, password: password}, nil
	}
	return nil, errors.New("could not choose a unique temporary account name")
}

func (a *temporaryWindowsAccount) login() (windows.Token, error) {
	name, err := windows.UTF16PtrFromString(a.name)
	if err != nil {
		return 0, err
	}
	password, err := windows.UTF16PtrFromString(a.password)
	if err != nil {
		return 0, err
	}
	domain, err := windows.UTF16PtrFromString(".")
	if err != nil {
		return 0, err
	}
	var token windows.Token
	proc := advapi32.NewProc("LogonUserW")
	r, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		logon32LogonInteractive,
		logon32ProviderDefault,
		uintptr(unsafe.Pointer(&token)),
	)
	if r == 0 {
		if callErr == nil {
			callErr = windows.GetLastError()
		}
		return 0, fmt.Errorf("LogonUserW temporary standard account: %w", callErr)
	}
	return token, nil
}

func (a *temporaryWindowsAccount) remove() error {
	name, err := windows.UTF16PtrFromString(a.name)
	if err != nil {
		return err
	}
	code, callErr := netUserDel(name)
	if callErr != nil && code != nerrUserNotFound {
		return callErr
	}
	return nil
}

func netUserAdd(info *windowsUserInfo1) (uint32, error) {
	proc := netapi32.NewProc("NetUserAdd")
	r, _, _ := proc.Call(0, 1, uintptr(unsafe.Pointer(info)), 0)
	code := uint32(r)
	if code != 0 {
		return code, fmt.Errorf("NetUserAdd returned code %d: %w", code, windows.Errno(code))
	}
	return 0, nil
}

func netUserDel(name *uint16) (uint32, error) {
	proc := netapi32.NewProc("NetUserDel")
	r, _, callErr := proc.Call(0, uintptr(unsafe.Pointer(name)))
	code := uint32(r)
	if code != 0 {
		if callErr == nil {
			callErr = windows.Errno(code)
		}
		return code, fmt.Errorf("NetUserDel returned code %d: %w", code, callErr)
	}
	return 0, nil
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
	cmd.Dir = filepath.Dir(path)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}
