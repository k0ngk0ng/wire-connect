//go:build !windows

package localctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnixEndpointPermissionsAndCloseCleanup(t *testing.T) {
	dir := testDirectory(t)
	server, err := Listen(context.Background(), dir, "secure", func() any { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	socket := endpointPath(dir, "secure")
	lock := lockPath(dir, "secure")
	socketInfo, err := os.Lstat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if socketInfo.Mode().Perm() != 0600 {
		t.Fatalf("socket mode = %o, want 600", socketInfo.Mode().Perm())
	}
	lockInfo, err := os.Lstat(lock)
	if err != nil {
		t.Fatal(err)
	}
	if lockInfo.Mode().Perm() != 0600 {
		t.Fatalf("lock mode = %o, want 600", lockInfo.Mode().Perm())
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("directory mode = %o, want 700", dirInfo.Mode().Perm())
	}
	if err := os.Chmod(socket, 0644); err != nil {
		t.Fatal(err)
	}
	var status any
	if err := Status(context.Background(), dir, "secure", &status); err == nil {
		t.Fatal("Status accepted a socket with public permissions")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket after Close: %v, want not exist", err)
	}
	if _, err := os.Lstat(lock); err != nil {
		t.Fatalf("lock after Close: %v, want persistent lock file", err)
	}
}

func TestUnixExistingDirectoryPermissionsAreRejectedWithoutRewrite(t *testing.T) {
	dir := testDirectory(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(context.Background(), dir, "unsafe-dir", func() any { return nil }, nil); err == nil {
		t.Fatal("Listen accepted a group/world-accessible directory")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Fatalf("directory mode after rejection = %o, want unchanged 755", got)
	}
}

func TestUnixStaleSocketRemovedOnlyAfterLock(t *testing.T) {
	dir := testDirectory(t)
	path := endpointPath(dir, "stale")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("stale socket = %v, info=%v", err, info)
	}
	server, err := Listen(context.Background(), dir, "stale", func() any { return "ok" }, nil)
	if err != nil {
		t.Fatalf("Listen with stale socket: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUnixStaleSocketIsUntouchedWhenLockIsHeld(t *testing.T) {
	dir := testDirectory(t)
	path := endpointPath(dir, "held")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireProfileLock(dir, "held")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := Listen(context.Background(), dir, "held", func() any { return nil }, nil); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("Listen error = %v, want ErrAlreadyRunning", err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("stale socket after lock rejection: %v, info=%v", err, info)
	}
}

func TestUnixInjectedSymlinkPathsRejected(t *testing.T) {
	for _, target := range []string{"directory", "lock", "socket"} {
		t.Run(target, func(t *testing.T) {
			dir := testDirectory(t)
			name := "injected"
			listenDir := dir
			switch target {
			case "directory":
				realDir := filepath.Join(dir, "real")
				if err := os.Mkdir(realDir, 0700); err != nil {
					t.Fatal(err)
				}
				listenDir = filepath.Join(dir, "alias")
				if err := os.Symlink(realDir, listenDir); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.Symlink(filepath.Join(dir, "target"), lockPath(dir, name)); err != nil {
					t.Fatal(err)
				}
			case "socket":
				targetPath := filepath.Join(dir, "target")
				if err := os.Symlink(targetPath, endpointPath(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Listen(context.Background(), listenDir, name, func() any { return nil }, nil); err == nil {
				t.Fatal("Listen unexpectedly accepted injected path")
			}
			if target == "socket" {
				var out any
				if err := Status(context.Background(), dir, name, &out); err == nil {
					t.Fatal("Status unexpectedly followed injected endpoint")
				}
			}
		})
	}
	t.Run("intermediate-directory", func(t *testing.T) {
		dir := testDirectory(t)
		realDir := filepath.Join(dir, "real")
		if err := os.Mkdir(realDir, 0700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(dir, "alias")
		if err := os.Symlink(realDir, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := Listen(context.Background(), filepath.Join(alias, "child"), "profile", func() any { return nil }, nil); err == nil {
			t.Fatal("Listen unexpectedly followed intermediate symlink")
		}
	})
}

func TestUnixSocketPathLengthError(t *testing.T) {
	base := testDirectory(t)
	longPart := strings.Repeat("x", 70)
	dir := filepath.Join(base, longPart)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	_, err := Listen(context.Background(), dir, "profile", func() any { return nil }, nil)
	if !errors.Is(err, ErrSocketPathTooLong) {
		t.Fatalf("Listen error = %v, want ErrSocketPathTooLong", err)
	}
}

func TestUnixNonSocketEndpointRejected(t *testing.T) {
	dir := testDirectory(t)
	if err := os.WriteFile(endpointPath(dir, "regular"), []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(context.Background(), dir, "regular", func() any { return nil }, nil); err == nil {
		t.Fatal("Listen accepted regular file endpoint")
	}
}

func TestUnixLockFileIsPersistent(t *testing.T) {
	dir := testDirectory(t)
	server, err := Listen(context.Background(), dir, "persistent", func() any { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lockPath(dir, "persistent")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(lockPath(dir, "persistent")); err != nil {
		t.Fatal(err)
	}
}
