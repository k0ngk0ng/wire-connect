//go:build !windows

package config

import (
	"fmt"
	"os"
)

func protect(path string, dir bool) error {
	mode := os.FileMode(0600)
	if dir {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
func checkPrivate(st os.FileInfo) error {
	if st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("state file %s is readable by other users; require mode 0600", st.Name())
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
