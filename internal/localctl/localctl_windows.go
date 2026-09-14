//go:build windows

package localctl

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

type windowsProfileLock struct {
	file       *os.File
	overlapped windows.Overlapped
	closeOnce  sync.Once
	closeErr   error
}

func (l *windowsProfileLock) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		err := windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped)
		if err != nil && !errors.Is(err, windows.ERROR_NOT_LOCKED) {
			l.closeErr = err
		}
		if closeErr := l.file.Close(); l.closeErr == nil {
			l.closeErr = closeErr
		}
	})
	return l.closeErr
}

func checkEndpointLength(_, _ string) error { return nil }

func endpointPath(dir, name string) string {
	// A profile's Windows endpoint is a named pipe rather than a filesystem
	// entry. Hashing the canonical profile coordinates keeps pipe names short
	// and prevents two state directories using the same name from colliding.
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(dir)) + "\x00" + strings.ToLower(name)))
	return `\\.\pipe\wire-connect-` + fmt.Sprintf("%x", sum[:16])
}

func lockPath(dir, name string) string {
	return filepath.Join(dir, name+".lock")
}

func acquireProfileLock(dir, name string) (profileLock, error) {
	path := lockPath(dir, name)
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("local control lock path must not be a symlink")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect local control lock: %w", err)
	}
	name16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("open local control lock: %w", err)
	}
	handle, err := windows.CreateFile(
		name16,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		// Keep delete sharing disabled while the profile is active. This
		// preserves the lock-file inode/name pair for the whole process
		// lifetime, matching the Unix persistent lock-file behavior.
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open local control lock: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.Close(handle)
		return nil, errors.New("open local control lock: invalid file")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect local control lock: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = file.Close()
		return nil, errors.New("local control lock must be a regular file")
	}
	if fileType, err := windows.GetFileType(handle); err != nil || fileType != windows.FILE_TYPE_DISK {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("inspect local control lock: %w", err)
		}
		return nil, errors.New("local control lock must be a regular file")
	}
	lock := &windowsProfileLock{file: file}
	err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.overlapped)
	if err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("lock local control profile: %w", err)
	}
	return lock, nil
}

func listenEndpoint(dir, name string) (net.Listener, func() error, error) {
	path := endpointPath(dir, name)
	sddl, err := pipeSecurityDescriptor()
	if err != nil {
		return nil, nil, fmt.Errorf("get local control pipe ACL: %w", err)
	}
	listener, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    requestBodyLimit,
		OutputBufferSize:   responseBodyLimit,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("listen local control pipe: %w", err)
	}
	return listener, func() error { return nil }, nil
}

func pipeSecurityDescriptor() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	if user == nil || user.User.Sid == nil {
		return "", errors.New("token has no user SID")
	}
	return pipeSecurityDescriptorFor(user.User.Sid), nil
}

func pipeSecurityDescriptorFor(user *windows.SID) string {
	if user != nil && user.IsWellKnown(windows.WinLocalSystemSid) {
		// A LocalSystem service must be reachable by an administrator running
		// the CLI. The service account itself is already SYSTEM, so granting
		// only the current SID would make the pipe SYSTEM-only.
		return "D:P(A;;GA;;;BA)(A;;GA;;;SY)"
	}
	if user == nil {
		return ""
	}
	return "D:P(A;;GA;;;" + user.String() + ")(A;;GA;;;SY)"
}

func dialEndpoint(ctx context.Context, dir, name string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, endpointPath(dir, name))
}

func validateClientEndpoint(_, _ string) error { return nil }

// A missing named pipe is reported as FILE_NOT_FOUND (and on some Windows
// versions as PATH_NOT_FOUND).  These are the only dial errors that prove the
// local control server is absent.  Access-denied and timeout errors may come
// from a live service and must remain unavailable diagnostics.
func isNotRunningError(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}
