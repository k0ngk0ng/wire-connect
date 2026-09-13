//go:build !windows

package localctl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type unixProfileLock struct {
	file      *os.File
	closeOnce sync.Once
	closeErr  error
}

func (l *unixProfileLock) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		if err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN); err != nil {
			l.closeErr = err
		}
		if err := l.file.Close(); l.closeErr == nil {
			l.closeErr = err
		}
	})
	return l.closeErr
}

func checkEndpointLength(dir, name string) error {
	path := endpointPath(dir, name)
	if len(path) >= unixSocketPathLimit {
		return fmt.Errorf("%w: %q has %d bytes (limit %d)", ErrSocketPathTooLong, path, len(path), unixSocketPathLimit-1)
	}
	return nil
}

func endpointPath(dir, name string) string {
	return filepath.Join(dir, name+".sock")
}

func lockPath(dir, name string) string {
	return filepath.Join(dir, name+".lock")
}

func acquireProfileLock(dir, name string) (profileLock, error) {
	path := lockPath(dir, name)
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("local control lock path must not be a symlink")
		}
		return nil, fmt.Errorf("open local control lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open local control lock: invalid file")
	}
	st, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat local control lock: %w", statErr)
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		_ = file.Close()
		return nil, errors.New("local control lock must be a regular file")
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("protect local control lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("lock local control profile: %w", err)
	}
	return &unixProfileLock{file: file}, nil
}

func listenEndpoint(dir, name string) (net.Listener, func() error, error) {
	path := endpointPath(dir, name)
	if err := prepareSocket(path); err != nil {
		return nil, nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, fmt.Errorf("listen local control socket: %w", err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return nil, nil, fmt.Errorf("stat local control socket: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 || st.Mode()&os.ModeSocket == 0 {
		_ = listener.Close()
		return nil, nil, errors.New("local control endpoint must be a real socket")
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		return nil, nil, fmt.Errorf("protect local control socket: %w", err)
	}
	id := unixFileID(st)
	cleanup := func() error {
		current, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect local control socket cleanup: %w", err)
		}
		if current.Mode()&os.ModeSymlink != 0 || current.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to remove replaced local control endpoint")
		}
		if id != unixFileID(current) {
			return errors.New("refusing to remove replaced local control socket")
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove local control socket: %w", err)
		}
		return nil
	}
	return listener, cleanup, nil
}

func prepareSocket(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect local control socket: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return errors.New("local control socket path must not be a symlink")
	}
	if st.Mode()&os.ModeSocket == 0 {
		return errors.New("local control endpoint exists and is not a socket")
	}
	id := unixFileID(st)
	conn, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return ErrAlreadyRunning
	}
	if !socketDialProvesInactive(dialErr) {
		return fmt.Errorf("cannot prove existing local control socket is inactive: %w", dialErr)
	}
	// The profile lock is held by the caller before this function runs. A
	// socket is removed only after it has been checked as a real, inactive
	// socket, never by blindly unlinking an arbitrary path.
	current, err := os.Lstat(path)
	if err == nil && current.Mode()&os.ModeSymlink == 0 && current.Mode()&os.ModeSocket != 0 && unixFileID(current) == id {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale local control socket: %w", err)
		}
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("recheck local control socket: %w", err)
	}
	return errors.New("refusing to remove replaced local control endpoint")
}

func socketDialProvesInactive(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, syscall.ENOTSOCK) ||
		errors.Is(err, syscall.ECONNRESET)
}

func validateClientEndpoint(dir, name string) error {
	path := endpointPath(dir, name)
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("local control endpoint: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return errors.New("local control endpoint path must not be a symlink")
	}
	if st.Mode()&os.ModeSocket == 0 {
		return errors.New("local control endpoint is not a socket")
	}
	if st.Mode().Perm()&0077 != 0 {
		return errors.New("local control endpoint is accessible by other users")
	}
	return nil
}

func unixFileID(info os.FileInfo) [2]uint64 {
	var id [2]uint64
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		id[0] = uint64(st.Dev)
		id[1] = uint64(st.Ino)
	}
	return id
}

func dialEndpoint(ctx context.Context, dir, name string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", endpointPath(dir, name))
}
