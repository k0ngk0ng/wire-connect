//go:build !windows

package config

import (
	"fmt"
	"os"
	"syscall"
)

func protect(path string, dir bool) error {
	mode := os.FileMode(0600)
	if dir {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
func checkPrivateDir(path string, st os.FileInfo) error {
	if err := checkOwner(path, st); err != nil {
		return err
	}
	if st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("state directory %s is accessible by other users; require mode 0700", path)
	}
	return nil
}
func checkPrivate(path string, st os.FileInfo) error {
	if err := checkOwner(path, st); err != nil {
		return err
	}
	if st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("state file %s is readable by other users; require mode 0600", path)
	}
	return nil
}

func checkOwner(path string, st os.FileInfo) error {
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("state path %s has unsupported owner metadata", path)
	}
	euid := os.Geteuid()
	if euid < 0 || uint64(stat.Uid) != uint64(euid) {
		return fmt.Errorf("state path %s is owned by uid %d; current uid is %d", path, stat.Uid, euid)
	}
	return nil
}
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func replaceFile(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }
