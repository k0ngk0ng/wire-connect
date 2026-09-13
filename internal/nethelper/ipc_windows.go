//go:build windows

package nethelper

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"
	"unsafe"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

func pipeName(id string) string {
	h := sha256.Sum256([]byte(id))
	return `\\.\pipe\wire-connect-nethelper-` + fmt.Sprintf("%x", h[:12])
}
func currentSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	if u == nil || u.User.Sid == nil {
		return "", errors.New("current process token has no user SID")
	}
	return u.User.Sid.String(), nil
}
func validSID(id string) error {
	s, err := windows.StringToSid(id)
	if err != nil {
		return err
	}
	if s.String() != id {
		return errors.New("noncanonical helper user SID")
	}
	return nil
}
func trustedOwner(handle windows.Handle, kind windows.SE_OBJECT_TYPE) error {
	sd, err := windows.GetSecurityInfo(handle, kind, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	if sd == nil {
		return errors.New("network helper object has no security descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || (!owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return errors.New("network helper object is not owned by SYSTEM or Administrators")
	}
	return nil
}
func dial(ctx context.Context) (net.Conn, error) {
	id, err := currentSID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := winio.DialPipeContext(ctx, pipeName(id))
	if err != nil {
		return nil, err
	}
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		c.Close()
		return nil, errors.New("helper pipe has no inspectable handle")
	}
	if err := trustedOwner(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

const pipeClientRights = "GRGW"

func pipeSecurityDescriptor(id string) string {
	// The enrolled user needs only to exchange bytes and wait on the pipe. In
	// particular, do not grant GA: WRITE_DAC would let that user authorize a
	// different SID and bypass the per-user service boundary.
	return "D:P(A;;" + pipeClientRights + ";;;" + id + ")(A;;GA;;;SY)(A;;GA;;;BA)"
}

func listen(id string) (net.Listener, func() error, error) {
	if err := validSID(id); err != nil {
		return nil, nil, err
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, nil, errors.New("network helper must run as SYSTEM or administrator")
	}
	// go-winio creates the first pipe instance exclusively and rejects remote
	// clients. Only this explicitly enrolled SID and OS administrators may open it.
	listener, err := winio.ListenPipe(pipeName(id), &winio.PipeConfig{SecurityDescriptor: pipeSecurityDescriptor(id), InputBufferSize: 128 * 1024, OutputBufferSize: 128 * 1024})
	if err != nil {
		return nil, nil, err
	}
	return listener, listener.Close, nil
}

func authenticate(c net.Conn, id string) error {
	if err := validSID(id); err != nil {
		return err
	}
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("helper pipe has no inspectable handle")
	}
	handle := windows.Handle(f.Fd())
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(handle, &pid); err != nil {
		return fmt.Errorf("get helper pipe client process: %w", err)
	}
	if pid == 0 {
		return errors.New("helper pipe has no client process")
	}
	clientSID, err := pipeClientSID(pid)
	if err != nil {
		return err
	}
	if clientSID != id {
		return errors.New("unauthorized network helper client")
	}
	return nil
}

func pipeClientSID(pid uint32) (string, error) {
	var lastErr error
	// PROCESS_QUERY_LIMITED_INFORMATION is sufficient on supported Windows
	// versions and avoids requesting broader process access. The fallback keeps
	// compatibility with systems where OpenProcessToken still requires
	// PROCESS_QUERY_INFORMATION.
	for _, access := range []uint32{windows.PROCESS_QUERY_LIMITED_INFORMATION, windows.PROCESS_QUERY_INFORMATION} {
		process, err := windows.OpenProcess(access, false, pid)
		if err != nil {
			lastErr = err
			continue
		}
		var token windows.Token
		err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token)
		_ = windows.CloseHandle(process)
		if err != nil {
			lastErr = err
			continue
		}
		user, err := token.GetTokenUser()
		_ = token.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if user == nil || user.User.Sid == nil {
			lastErr = errors.New("helper pipe client token has no user SID")
			continue
		}
		return user.User.Sid.String(), nil
	}
	return "", fmt.Errorf("inspect helper pipe client token: %w", lastErr)
}

func networkLock(ctx context.Context) (func(), error) {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(`Global\WireConnectNetworkSetup`)
	h, err := windows.CreateMutex(&sa, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, err
	}
	if err := trustedOwner(h, windows.SE_KERNEL_OBJECT); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	runtime.LockOSThread()
	for {
		state, err := windows.WaitForSingleObject(h, 20)
		if err != nil {
			runtime.UnlockOSThread()
			windows.CloseHandle(h)
			return nil, err
		}
		if state == windows.WAIT_OBJECT_0 || state == windows.WAIT_ABANDONED {
			return func() { _ = windows.ReleaseMutex(h); _ = windows.CloseHandle(h); runtime.UnlockOSThread() }, nil
		}
		if state != uint32(windows.WAIT_TIMEOUT) {
			runtime.UnlockOSThread()
			windows.CloseHandle(h)
			return nil, errors.New("network helper mutex wait failed")
		}
		if err := ctx.Err(); err != nil {
			runtime.UnlockOSThread()
			windows.CloseHandle(h)
			return nil, err
		}
	}
}
