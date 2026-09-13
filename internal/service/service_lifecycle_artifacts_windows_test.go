//go:build windows && amd64

package service

import (
	"errors"
	"os"
)

func integrationInstalledArtifacts(name string) (bool, error) {
	dir, err := windowsInstalledDir(name)
	if err != nil {
		return false, err
	}
	_, err = os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return true, err
}
