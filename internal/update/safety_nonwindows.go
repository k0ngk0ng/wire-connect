//go:build !windows

package update

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// An elevated updater must not execute its replacement from a directory
// controlled by an ordinary user. Mode checks alone do not establish that
// boundary: an owner can change a 0755 directory at any time.
func validateUpdateDestinationSecurity(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil {
			return err
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return fmt.Errorf("wire-connect: elevated update requires root-owned installation paths; run update as the installation owner: %q", current)
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}
