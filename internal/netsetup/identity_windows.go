//go:build windows && amd64

package netsetup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func currentIdentity() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("wire-connect: get current Windows user SID: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return "", errors.New("wire-connect: current Windows token has no user SID")
	}
	sid := user.User.Sid.String()
	if sid == "" {
		return "", errors.New("wire-connect: current Windows token returned an empty user SID")
	}
	return sid, nil
}

func normalizeIdentity(identity string) (string, error) {
	if identity == "" {
		return "", errors.New("wire-connect: helper identity is required")
	}
	sid, err := windows.StringToSid(identity)
	if err != nil {
		return "", fmt.Errorf("wire-connect: helper identity %q is not a valid SID: %w", identity, err)
	}
	canonical := sid.String()
	if canonical == "" || canonical != identity {
		return "", fmt.Errorf("wire-connect: helper identity %q is not canonical", identity)
	}
	return canonical, nil
}

func validateExecutablePlatform(os.FileInfo) error { return nil }

func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// The Windows shell elevation API does not attach the elevated process to the
// caller's stdio handles.  Ensure still waits for its process handle and
// returns the child exit status; the caller's terminal receives diagnostics
// from this process when the operation fails.
func requestElevation(ctx context.Context, executable, identity string, _ io.Reader, _, errOut io.Writer) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if errOut == nil {
		errOut = io.Discard
	}
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	parameters, err := windows.UTF16PtrFromString("__setup-network --identity " + syscall.EscapeArg(identity))
	if err != nil {
		return err
	}
	info := shellExecuteInfo{
		cbSize:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: parameters,
		nShow:        windows.SW_SHOWNORMAL,
	}
	if err := shellExecuteEx(&info); err != nil {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return errors.New("wire-connect: administrator authorization was cancelled")
		}
		return fmt.Errorf("wire-connect: request administrator authorization with UAC: %w", err)
	}
	if info.hProcess == 0 {
		return errors.New("wire-connect: UAC did not return an elevated process handle")
	}
	defer windows.Close(info.hProcess)
	for {
		if err := contextErr(ctx); err != nil {
			return err
		}
		result, err := windows.WaitForSingleObject(info.hProcess, 100)
		if err != nil {
			return fmt.Errorf("wire-connect: wait for elevated setup: %w", err)
		}
		if result == uint32(windows.WAIT_TIMEOUT) {
			continue
		}
		if result != uint32(windows.WAIT_OBJECT_0) {
			return fmt.Errorf("wire-connect: wait for elevated setup returned 0x%x", result)
		}
		var exitCode uint32
		if err := windows.GetExitCodeProcess(info.hProcess, &exitCode); err != nil {
			return fmt.Errorf("wire-connect: read elevated setup result: %w", err)
		}
		if exitCode != 0 {
			return fmt.Errorf("wire-connect: elevated setup exited with status %d", exitCode)
		}
		return nil
	}
}

const seeMaskNoCloseProcess = 0x00000040

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         windows.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     windows.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    windows.Handle
	dwHotKey     uint32
	hIcon        windows.Handle
	hProcess     windows.Handle
}

var shellExecuteExProc = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

func shellExecuteEx(info *shellExecuteInfo) error {
	result, _, callErr := shellExecuteExProc.Call(uintptr(unsafe.Pointer(info)))
	if result != 0 {
		return nil
	}
	if callErr != nil && callErr != syscall.Errno(0) {
		return callErr
	}
	return windows.ERROR_GEN_FAILURE
}
