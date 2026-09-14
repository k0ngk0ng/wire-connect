//go:build !windows

// Package installpath resolves installed files through package-manager launchers.
package installpath

import "path/filepath"

// Resolve returns the absolute path after following filesystem links.
func Resolve(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(absolute)
}
