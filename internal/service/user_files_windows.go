//go:build windows && amd64

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

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
	return nil
}

func windowsUserInstallBase() (string, error) {
	base := userGetenv("LOCALAPPDATA")
	if base == "" {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("wire-connect: determine current user data directory: %w", err)
		}
	}
	if !filepath.IsAbs(base) {
		return "", fmt.Errorf("wire-connect: current user data directory %q is not absolute", base)
	}
	st, err := os.Lstat(filepath.Clean(base))
	if err != nil {
		return "", fmt.Errorf("wire-connect: inspect current user data directory %q: %w", base, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return "", fmt.Errorf("wire-connect: current user data directory %q is not a real directory", base)
	}
	return filepath.Clean(base), nil
}

func windowsUserPath(name string) (string, error) {
	base, err := windowsUserInstallBase()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "wire-connect", name), nil
}

func windowsUserInstalledDir(name string) (string, error) {
	return windowsUserPath(name)
}

func windowsUserInstalledExecutable(name string) (string, error) {
	dir, err := windowsUserInstalledDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wirectl-connect.exe"), nil
}

func windowsUserEnsureDir(path string) error {
	base, err := windowsUserInstallBase()
	if err != nil {
		return err
	}
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(base, clean)
	if err != nil || filepath.IsAbs(rel) || rel == "." || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return fmt.Errorf("wire-connect: user installation path %q is outside current user data directory", path)
	}
	if err := os.MkdirAll(clean, 0700); err != nil {
		return fmt.Errorf("wire-connect: create user installation directory %q: %w", clean, err)
	}
	// Inspect every package component so a reparse point cannot redirect a
	// later copy or deletion outside the current user's data directory.
	current := base
	for _, part := range strings.Split(filepath.Clean(rel), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		st, statErr := os.Lstat(current)
		if statErr != nil {
			return fmt.Errorf("wire-connect: inspect user installation directory %q: %w", current, statErr)
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("wire-connect: user installation path %q is not a real directory", current)
		}
		if err := windowsUserProtectPath(current, true); err != nil {
			return fmt.Errorf("wire-connect: protect user installation directory %q: %w", current, err)
		}
	}
	if err := windowsUserProtectPath(clean, true); err != nil {
		return fmt.Errorf("wire-connect: protect user installation directory %q: %w", clean, err)
	}
	return nil
}

func windowsUserCopyAtomic(ctx context.Context, source, destination string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateUserSource(source); err != nil {
		return err
	}
	if err := windowsUserEnsureDir(filepath.Dir(destination)); err != nil {
		return err
	}
	if st, err := os.Lstat(destination); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return fmt.Errorf("wire-connect: refusing to replace non-regular installed user file %q", destination)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	src, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("wire-connect: open user file source: %w", err)
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".wire-connect-user-*.tmp")
	if err != nil {
		return fmt.Errorf("wire-connect: create user file temporary: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, src); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: copy user file: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := windowsUserProtectPath(tmpPath, false); err != nil {
		return fmt.Errorf("wire-connect: protect user file: %w", err)
	}
	if err := windowsRenameWithRetry(ctx, tmpPath, destination, windowsFileReplaceWait); err != nil {
		return fmt.Errorf("wire-connect: install user file: %w", err)
	}
	return nil
}

func windowsUserWriteTaskXML(ctx context.Context, directory string, data []byte) (string, error) {
	if err := contextErr(ctx); err != nil {
		return "", err
	}
	if err := windowsUserEnsureDir(directory); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(directory, ".wire-connect-user-*.xml")
	if err != nil {
		return "", fmt.Errorf("wire-connect: create scheduled task definition: %w", err)
	}
	path := f.Name()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("wire-connect: write scheduled task definition: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := windowsUserProtectPath(path, false); err != nil {
		return "", fmt.Errorf("wire-connect: protect scheduled task definition: %w", err)
	}
	remove = false
	return path, nil
}

func windowsUserRemoveDir(path string) error {
	base, err := windowsUserInstallBase()
	if err != nil {
		return err
	}
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(filepath.Join(base, "wire-connect"), clean)
	if err != nil || filepath.IsAbs(rel) || rel == "." || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return fmt.Errorf("wire-connect: refusing to remove user path outside package root: %q", path)
	}
	st, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := windowsUserValidateExistingPath(clean, base); err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("wire-connect: refusing to remove non-directory user installation %q", clean)
	}
	return os.RemoveAll(clean)
}

func windowsUserDirectoryExists(path string) (bool, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	base, err := windowsUserInstallBase()
	if err != nil {
		return false, err
	}
	if err := windowsUserValidateExistingPath(path, base); err != nil {
		return false, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return false, fmt.Errorf("wire-connect: user installation %q is not a real directory", path)
	}
	return true, nil
}

func windowsUserValidateExistingPath(path, base string) error {
	cleanBase := filepath.Clean(base)
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(filepath.Join(cleanBase, "wire-connect"), clean)
	if err != nil || filepath.IsAbs(rel) || rel == "." || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return fmt.Errorf("wire-connect: user path %q is outside package root", path)
	}
	root := filepath.Join(cleanBase, "wire-connect")
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect user package root %q: %w", root, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return fmt.Errorf("wire-connect: user package root %q is not a real directory", root)
	}
	current := root
	for _, part := range strings.Split(filepath.Clean(rel), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		st, statErr := os.Lstat(current)
		if statErr != nil {
			return fmt.Errorf("wire-connect: inspect user installation path %q: %w", current, statErr)
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("wire-connect: user installation path %q is not a real directory", current)
		}
	}
	return nil
}

func windowsUserProtectPath(path string, directory bool) error {
	token := windows.GetCurrentProcessToken()
	userInfo, err := token.GetTokenUser()
	if err != nil || userInfo == nil || userInfo.User.Sid == nil {
		if err == nil {
			err = errors.New("token has no user SID")
		}
		return fmt.Errorf("get current Windows user SID: %w", err)
	}
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sddl := fmt.Sprintf("D:P(A;%s;FA;;;%s)", inherit, userInfo.User.Sid.String())
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
