//go:build linux || darwin

package nethelper

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const socketDirectory = "/var/run/wire-connect-nethelper"

func identity() string            { return strconv.Itoa(os.Geteuid()) }
func socketName(id string) string { h := sha256.Sum256([]byte(id)); return fmt.Sprintf("%x", h[:12]) }
func validateIdentity(id string) (uint32, error) {
	n, err := strconv.ParseUint(id, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != id {
		return 0, errors.New("invalid helper user identity")
	}
	return uint32(n), nil
}
func rootDirectory(create bool) error {
	if create {
		if err := os.Mkdir(socketDirectory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	st, err := os.Lstat(socketDirectory)
	if err != nil {
		return err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || st.Mode().Perm()&0022 != 0 {
		return errors.New("network helper directory is not protected by root")
	}
	return nil
}
func dial(ctx context.Context) (net.Conn, error) {
	if err := rootDirectory(false); err != nil {
		return nil, err
	}
	path := filepath.Join(socketDirectory, socketName(identity())+".sock")
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("untrusted network helper socket")
	}
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	uid, err := peerUID(c)
	if err != nil || uid != 0 {
		c.Close()
		return nil, errors.New("network helper peer is not root")
	}
	return c, nil
}
func listen(id string) (net.Listener, func() error, error) {
	uid, err := validateIdentity(id)
	if err != nil {
		return nil, nil, err
	}
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("network helper must run as root")
	}
	if err := rootDirectory(true); err != nil {
		return nil, nil, err
	}
	lock, err := lockFile(filepath.Join(socketDirectory, socketName(id)+".lock"))
	if err != nil {
		return nil, nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, nil, err
	}
	path := filepath.Join(socketDirectory, socketName(id)+".sock")
	if st, err := os.Lstat(path); err == nil {
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || st.Mode()&os.ModeSocket == 0 || stat.Uid != uid {
			lock.Close()
			return nil, nil, errors.New("refusing to replace unexpected helper socket")
		}
		if err := os.Remove(path); err != nil {
			lock.Close()
			return nil, nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		lock.Close()
		return nil, nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		lock.Close()
		return nil, nil, err
	}
	fail := func(err error) (net.Listener, func() error, error) {
		listener.Close()
		lock.Close()
		return nil, nil, err
	}
	// Parent directory remains root-owned: the authorized user may connect but
	// cannot replace the endpoint with an impersonating server.
	if err := os.Chown(path, int(uid), -1); err != nil {
		return fail(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fail(err)
	}
	return listener, func() error { _ = listener.Close(); return lock.Close() }, nil
}
func authenticate(c net.Conn, id string) error {
	want, err := validateIdentity(id)
	if err != nil {
		return err
	}
	got, err := peerUID(c)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("unauthorized network helper client")
	}
	return nil
}
func lockFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || stat.Uid != 0 || st.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("unsafe helper lock")
	}
	return f, nil
}
func networkLock(ctx context.Context) (func(), error) {
	f, err := lockFile(filepath.Join(socketDirectory, "network.lock"))
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
