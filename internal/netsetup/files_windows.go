//go:build windows && amd64

package netsetup

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

var windowsProgramFilesPath = findWindowsProgramFiles

func findWindowsProgramFiles() (string, error) {
	path, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("wire-connect: locate Windows Program Files: %w", err)
	}
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("wire-connect: Windows returned an invalid Program Files path")
	}
	return filepath.Clean(path), nil
}

func windowsInstallRoot() (string, error) {
	programFiles, err := windowsProgramFilesPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(programFiles, "wire-connect"), nil
}

func windowsHelperDir(name string) (string, error) {
	root, err := windowsInstallRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, name), nil
}

func windowsHelperExecutable(name string) (string, error) {
	dir, err := windowsHelperDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wirectl-connect.exe"), nil
}

func windowsHelperWintun(name string) (string, error) {
	dir, err := windowsHelperDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wintun.dll"), nil
}

func windowsHelperLicense(name string) (string, error) {
	dir, err := windowsHelperDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "WINTUN-LICENSE.txt"), nil
}

func validateWindowsSource(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("wire-connect: helper source %q must be absolute", path)
	}
	st, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("wire-connect: inspect helper source %q: %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: helper source %q must be a regular file, not a symlink", path)
	}
	return nil
}

func ensureWindowsInstallParent(destination string) error {
	root, err := windowsInstallRoot()
	if err != nil {
		return err
	}
	root = filepath.Clean(root)
	destination = filepath.Clean(destination)
	rel, err := filepath.Rel(root, destination)
	if err != nil || filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("wire-connect: refusing to install outside Program Files package root: %q", destination)
	}
	programFiles := filepath.Dir(root)
	st, err := os.Lstat(programFiles)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect Program Files %q: %w", programFiles, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("wire-connect: Program Files %q is not a real directory", programFiles)
	}
	parent := filepath.Dir(destination)
	rel, err = filepath.Rel(programFiles, parent)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("wire-connect: helper package directory is outside Program Files")
	}
	current := programFiles
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0755); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("wire-connect: create protected helper directory %q: %w", current, err)
			}
			st, err = os.Lstat(current)
		}
		if err != nil {
			return fmt.Errorf("wire-connect: inspect protected helper directory %q: %w", current, err)
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("wire-connect: helper package directory %q is not a real directory", current)
		}
		if err := setWindowsProtectedACL(current, true); err != nil {
			return fmt.Errorf("wire-connect: protect helper directory %q: %w", current, err)
		}
	}
	return nil
}

func validateWindowsDestination(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: refusing to replace non-regular helper file %q", path)
	}
	return nil
}

func copyWindowsProtected(ctx context.Context, source, destination string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateWindowsSource(source); err != nil {
		return err
	}
	if err := ensureWindowsInstallParent(destination); err != nil {
		return err
	}
	if err := validateWindowsDestination(destination); err != nil {
		return err
	}
	src, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("wire-connect: open helper source %q: %w", source, err)
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".wire-connect-helper-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, src); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: copy helper file: %w", err)
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
	if err := setWindowsProtectedACL(tmpPath, false); err != nil {
		return fmt.Errorf("wire-connect: protect helper file: %w", err)
	}
	from, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("wire-connect: install protected helper file: %w", err)
	}
	return nil
}

func setWindowsProtectedACL(path string, directory bool) error {
	sddl := "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if directory {
		sddl = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	}
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

func removeWindowsInstalledDir(path string) error {
	root, err := windowsInstallRoot()
	if err != nil {
		return err
	}
	cleanRoot := filepath.Clean(root)
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(cleanRoot, clean)
	if err != nil || filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("wire-connect: refusing to remove helper path outside package root: %q", path)
	}
	if _, err := normalizeHelperName(filepath.Base(clean)); err != nil {
		return err
	}
	st, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("wire-connect: refusing to remove non-directory helper path %q", path)
	}
	return os.RemoveAll(clean)
}
