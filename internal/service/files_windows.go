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
	"time"

	"golang.org/x/sys/windows"
)

type windowsFileOperator struct{}

var (
	platformFiles          fileOperator = windowsFileOperator{}
	windowsProgramFiles                 = findProgramFiles
	windowsValidateSource               = validateWindowsSource
	windowsRename                       = windows.Rename
	windowsSetProtectedACL              = setWindowsProtectedACL
)

const (
	windowsFileReplaceWait          = 30 * time.Second
	windowsFileReplaceRetryInterval = 100 * time.Millisecond
)

func (windowsFileOperator) ValidateStateDir(ctx context.Context, path string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("wire-connect: state directory %q must be absolute", path)
	}
	st, err := os.Lstat(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("wire-connect: state directory %q must already exist; create an administrator-owned protected directory before installing the service", path)
	}
	if err != nil {
		return fmt.Errorf("wire-connect: inspect state directory %q: %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("wire-connect: state directory %q must be a real directory", path)
	}
	if err := validateWindowsProtectedDirectory(path); err != nil {
		return err
	}
	return nil
}

func (windowsFileOperator) CopyProtected(ctx context.Context, source, destination string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := ensureWindowsInstallParent(destination); err != nil {
		return err
	}
	if err := validateWindowsSource(source); err != nil {
		return err
	}
	return windowsCopyAtomic(ctx, source, destination)
}

func (windowsFileOperator) WriteProtected(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if mode.Perm() == 0 {
		return errors.New("wire-connect: protected file mode is empty")
	}
	if err := ensureTrustedWindowsRecordParent(path); err != nil {
		return err
	}
	return windowsWriteAtomic(ctx, path, data)
}

func (windowsFileOperator) RemoveFile(ctx context.Context, path string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: refusing to remove non-regular service record %q", path)
	}
	return os.Remove(path)
}

func (windowsFileOperator) RemoveDir(ctx context.Context, path string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateWindowsInstallDir(path); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("wire-connect: refusing to remove non-directory installation %q", path)
	}
	return os.RemoveAll(path)
}

func findProgramFiles() (string, error) {
	path, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("wire-connect: locate Program Files: %w", err)
	}
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("wire-connect: Windows returned an invalid Program Files path")
	}
	return filepath.Clean(path), nil
}

func windowsInstallRoot() (string, error) {
	programFiles, err := windowsProgramFiles()
	if err != nil {
		return "", err
	}
	return filepath.Join(programFiles, "wire-connect"), nil
}

func windowsInstalledDir(name string) (string, error) {
	root, err := windowsInstallRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, name), nil
}

func windowsInstalledExecutable(name string) (string, error) {
	dir, err := windowsInstalledDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wirectl-connect.exe"), nil
}

func windowsInstalledWintun(name string) (string, error) {
	dir, err := windowsInstalledDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wintun.dll"), nil
}

func validateWindowsSource(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("wire-connect: executable path %q must be absolute", path)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect executable %q: %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: executable %q must be a regular file, not a symlink", path)
	}
	return nil
}

func ensureWindowsInstallParent(destination string) error {
	root, err := windowsInstallRoot()
	if err != nil {
		return err
	}
	cleanRoot := filepath.Clean(root)
	cleanDestination := filepath.Clean(destination)
	rel, err := filepath.Rel(cleanRoot, cleanDestination)
	if err != nil || filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("wire-connect: refusing to install outside Program Files package root: %q", destination)
	}
	parent := filepath.Dir(cleanDestination)
	if err := ensureWindowsDirectoryTree(parent, cleanRoot); err != nil {
		return err
	}
	return nil
}

func validateWindowsInstallDir(path string) error {
	root, err := windowsInstallRoot()
	if err != nil {
		return err
	}
	cleanRoot := filepath.Clean(root)
	cleanPath := filepath.Clean(path)
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("wire-connect: refusing to remove path outside Program Files package root: %q", path)
	}
	if _, err := normalizeName(filepath.Base(cleanPath)); err != nil {
		return fmt.Errorf("wire-connect: refusing to remove invalid package installation %q", path)
	}
	return nil
}

func ensureWindowsDirectoryTree(path, root string) error {
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || filepath.IsAbs(rel) || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("wire-connect: directory %q is outside the protected package root", path)
	}
	// Program Files itself is owned by Windows and must never be rewritten by
	// this installer.  Only the package root and the named service directory
	// below it receive our explicit DACL.
	programFiles := filepath.Dir(cleanRoot)
	if st, err := os.Lstat(programFiles); err != nil {
		return fmt.Errorf("wire-connect: inspect Program Files %q: %w", programFiles, err)
	} else if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("wire-connect: Program Files %q is not a real directory", programFiles)
	}
	relativeToProgramFiles, err := filepath.Rel(programFiles, cleanPath)
	if err != nil || filepath.IsAbs(relativeToProgramFiles) {
		return fmt.Errorf("wire-connect: package directory %q is outside Program Files", cleanPath)
	}
	components := strings.Split(relativeToProgramFiles, string(filepath.Separator))
	current := programFiles
	for _, component := range components {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		st, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0755); err != nil {
				return fmt.Errorf("wire-connect: create protected package directory %q: %w", current, err)
			}
			st, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("wire-connect: package directory %q is not a real directory", current)
		}
		if err := setWindowsProtectedACL(current, true); err != nil {
			return fmt.Errorf("wire-connect: protect package directory %q: %w", current, err)
		}
	}
	return nil
}

func ensureTrustedWindowsRecordParent(path string) error {
	parent := filepath.Dir(filepath.Clean(path))
	st, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect service record directory %q: %w", parent, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("wire-connect: service record directory %q is not a real directory", parent)
	}
	return nil
}

func windowsCopyAtomic(ctx context.Context, source, destination string) error {
	src, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer src.Close()
	if err := contextErr(ctx); err != nil {
		return err
	}
	if st, err := os.Lstat(destination); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return fmt.Errorf("wire-connect: refusing to replace non-regular installed file %q", destination)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".wire-connect-*.tmp")
	if err != nil {
		return fmt.Errorf("create protected temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return fmt.Errorf("copy file: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := windowsSetProtectedACL(tmpPath, false); err != nil {
		return fmt.Errorf("protect installed file: %w", err)
	}
	if err := windowsRenameWithRetry(ctx, tmpPath, destination, windowsFileReplaceWait); err != nil {
		return fmt.Errorf("install protected file: %w", err)
	}
	return nil
}

func windowsWriteAtomic(ctx context.Context, path string, data []byte) error {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return fmt.Errorf("wire-connect: refusing to replace non-regular service record %q", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wire-connect-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := contextErr(ctx); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := windowsSetProtectedACL(tmpPath, false); err != nil {
		return err
	}
	if err := windows.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}

func windowsRenameWithRetry(ctx context.Context, oldPath, newPath string, timeout time.Duration) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if timeout <= 0 {
		return errors.New("invalid protected file replacement timeout")
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := contextErr(ctx); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr != nil {
				return fmt.Errorf("timed out replacing protected file: %w", lastErr)
			}
			return errors.New("timed out replacing protected file")
		}
		err := windowsRename(oldPath, newPath)
		if err == nil {
			return nil
		}
		if !windowsReplaceRetryable(err) {
			return err
		}
		lastErr = err
		remaining = time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("timed out replacing protected file: %w", lastErr)
		}
		waitFor := windowsFileReplaceRetryInterval
		if remaining < waitFor {
			waitFor = remaining
		}
		timer := time.NewTimer(waitFor)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func windowsReplaceRetryable(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

const windowsProtectedFileSDDL = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"
const windowsProtectedDirectorySDDL = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func setWindowsProtectedACL(path string, directory bool) error {
	sddl := windowsProtectedFileSDDL
	if directory {
		sddl = windowsProtectedDirectorySDDL
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

func validateWindowsProtectedDirectory(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect ACL for state directory %q: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("wire-connect: inspect state directory owner: %w", err)
	}
	if owner == nil || (!owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid)) {
		return fmt.Errorf("wire-connect: state directory %q must be owned by Administrators or SYSTEM", path)
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("wire-connect: inspect state directory ACL: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("wire-connect: state directory %q must have a protected DACL", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return fmt.Errorf("wire-connect: state directory %q must have an explicit administrator/SYSTEM DACL", path)
	}
	sddl := sd.String()
	for _, broad := range []string{";;;WD)", ";;;BU)", ";;;AU)"} {
		if strings.Contains(sddl, broad) {
			return fmt.Errorf("wire-connect: state directory %q grants access to a broad user group", path)
		}
	}
	if !strings.Contains(sddl, ";;;BA") || !strings.Contains(sddl, ";;;SY") {
		return fmt.Errorf("wire-connect: state directory %q must grant access to Administrators and SYSTEM", path)
	}
	return nil
}
