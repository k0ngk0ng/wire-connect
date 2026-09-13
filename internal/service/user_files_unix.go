//go:build (linux && (amd64 || arm64)) || (darwin && (amd64 || arm64))

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// userHomeDir is a variable so path-policy tests can use a repository-local
// home without touching a real user's launchd or systemd directories.
var userHomeDir = os.UserHomeDir

func validateUserSource(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("wire-connect: executable path %q must be absolute", path)
	}
	st, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("wire-connect: inspect executable %q: %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: executable %q must be a regular file, not a symlink", path)
	}
	if st.Mode()&0111 == 0 {
		return fmt.Errorf("wire-connect: executable %q is not executable", path)
	}
	return nil
}

func userCurrentUID() uint32 {
	return uint32(os.Geteuid())
}

func userPathUnderHome(path string) (string, string, error) {
	home, err := userHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("wire-connect: determine current user home: %w", err)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return "", "", fmt.Errorf("wire-connect: resolve current user home: %w", err)
	}
	home = filepath.Clean(home)
	if home == string(filepath.Separator) {
		return "", "", errors.New("wire-connect: refusing to use filesystem root as current user home")
	}
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(home, clean)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return "", "", fmt.Errorf("wire-connect: user service path %q is outside current user home %q", path, home)
	}
	return home, clean, nil
}

// userEnsureDir creates a package-owned private directory below the current
// user's home. Existing ancestors are accepted when they belong to the
// current user and cannot be replaced by another user; newly-created package
// directories are mode 0700.
func userEnsureDir(path string) error {
	return userEnsureDirMode(path, true)
}

// userEnsureDirMode is used for service-manager record directories as well as
// executable directories. Record directories may predate this package (for
// example ~/Library/LaunchAgents) and therefore need only ownership and
// non-writability checks, while package directories remain private.
func userEnsureDirMode(path string, private bool) error {
	home, clean, err := userPathUnderHome(path)
	if err != nil {
		return err
	}
	missing := make([]string, 0, 4)
	for current := clean; ; current = filepath.Dir(current) {
		st, statErr := os.Lstat(current)
		if statErr == nil {
			// Existing home/profile ancestors commonly use mode 0755. They are
			// safe when owned by this user and not writable by other users; only
			// the package leaf is required to be mode 0700.
			if err := validateUserDirectory(st, current, false); err != nil {
				return err
			}
			for i := len(missing) - 1; i >= 0; i-- {
				if err := makeUserDirectory(missing[i]); err != nil {
					return err
				}
			}
			return validateUserDirectoryPath(clean, private)
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("wire-connect: inspect user service directory %q: %w", current, statErr)
		}
		if current == home {
			return fmt.Errorf("wire-connect: current user home %q does not exist", home)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("wire-connect: user service path %q has no home ancestor", clean)
		}
	}
}

func makeUserDirectory(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("wire-connect: create user service directory %q: %w", path, err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect user service directory %q: %w", path, err)
	}
	return validateUserDirectory(st, path, true)
}

func validateUserDirectory(st os.FileInfo, path string, private bool) error {
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("wire-connect: user service path %q is not a real directory", path)
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("wire-connect: inspect owner of user service path %q: unsupported filesystem metadata", path)
	}
	uid := userCurrentUID()
	if uint32(stat.Uid) != uid {
		return fmt.Errorf("wire-connect: user service path %q is owned by uid %d; current uid is %d", path, stat.Uid, uid)
	}
	if st.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("wire-connect: user service path %q is writable by another user", path)
	}
	if private && st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("wire-connect: user service path %q must be private (mode 0700)", path)
	}
	return nil
}

func validateUserDirectoryPath(path string, private bool) error {
	_, clean, err := userPathUnderHome(path)
	if err != nil {
		return err
	}
	st, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	return validateUserDirectory(st, clean, private)
}

func validateUserFile(st os.FileInfo, path string) error {
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: user service path %q is not a regular file", path)
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("wire-connect: inspect owner of user service file %q: unsupported filesystem metadata", path)
	}
	if uint32(stat.Uid) != userCurrentUID() {
		return fmt.Errorf("wire-connect: user service file %q is not owned by the current user", path)
	}
	if st.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("wire-connect: user service file %q is writable by another user", path)
	}
	return nil
}

// userValidateExistingAncestors verifies the path chain without creating
// anything. It is used before status/removal operations, where creating a
// missing service-manager directory would be surprising and an ancestor
// symlink could otherwise redirect an operation outside the user profile.
func userValidateExistingAncestors(path string) error {
	home, clean, err := userPathUnderHome(path)
	if err != nil {
		return err
	}
	for current := filepath.Dir(clean); ; current = filepath.Dir(current) {
		st, statErr := os.Lstat(current)
		if statErr != nil {
			return fmt.Errorf("wire-connect: inspect user service path parent %q: %w", current, statErr)
		}
		if err := validateUserDirectory(st, current, false); err != nil {
			return err
		}
		if current == home {
			return nil
		}
	}
}

func userCopyAtomic(ctx context.Context, source, destination string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateUserSource(source); err != nil {
		return err
	}
	if err := userEnsureDir(filepath.Dir(destination)); err != nil {
		return err
	}
	if st, err := os.Lstat(destination); err == nil {
		if err := validateUserFile(st, destination); err != nil {
			return fmt.Errorf("wire-connect: refusing to replace installed user executable: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	src, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("wire-connect: open user executable source: %w", err)
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".wire-connect-user-*.tmp")
	if err != nil {
		return fmt.Errorf("wire-connect: create user executable temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0700); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, src); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: copy user executable: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: sync user executable: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("wire-connect: close user executable: %w", err)
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return fmt.Errorf("wire-connect: install user executable: %w", err)
	}
	return syncDirectory(filepath.Dir(destination))
}

func userWriteAtomic(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := userEnsureDirMode(filepath.Dir(path), false); err != nil {
		return err
	}
	if st, err := os.Lstat(path); err == nil {
		if err := validateUserFile(st, path); err != nil {
			return fmt.Errorf("wire-connect: refusing to replace user service record: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wire-connect-user-*.tmp")
	if err != nil {
		return fmt.Errorf("wire-connect: create user service record temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: write user service record: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: sync user service record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("wire-connect: close user service record: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("wire-connect: install user service record: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func userRemoveFile(path string) error {
	if err := userValidateExistingAncestors(path); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateUserFile(st, path); err != nil {
		return fmt.Errorf("wire-connect: refusing to remove user service record: %w", err)
	}
	return os.Remove(path)
}

func userRemoveDir(path string) error {
	home, clean, err := userPathUnderHome(path)
	if err != nil {
		return err
	}
	root := filepath.Join(userInstallBase(home), "wire-connect")
	rel, err := filepath.Rel(root, clean)
	if err != nil || rel == "." || rel == "" || filepath.IsAbs(rel) || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return fmt.Errorf("wire-connect: refusing to remove user path outside package root: %q", path)
	}
	st, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := userValidateExistingAncestors(clean); err != nil {
		return err
	}
	if err := validateUserDirectory(st, clean, true); err != nil {
		return fmt.Errorf("wire-connect: refusing to remove user installation: %w", err)
	}
	return os.RemoveAll(clean)
}

func userDirectoryExists(path string) (bool, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := userValidateExistingAncestors(path); err != nil {
		return false, err
	}
	if err := validateUserDirectory(st, path, true); err != nil {
		return false, err
	}
	return true, nil
}
