//go:build (linux && (amd64 || arm64)) || (darwin && (amd64 || arm64))

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const unixInstallRoot = "/usr/local/libexec/wire-connect"

// unixFileOperator keeps all privileged filesystem changes in one small
// implementation.  In particular, it never follows an existing symlink for
// a state, package, or service-record path.
type unixFileOperator struct{}

var platformFiles fileOperator = unixFileOperator{}

func (unixFileOperator) ValidateStateDir(ctx context.Context, path string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	return validateUnixStateDir(path)
}

func (unixFileOperator) CopyProtected(ctx context.Context, source, destination string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := ensureSecureInstallParent(filepath.Dir(destination)); err != nil {
		return err
	}
	if err := validateSourceExecutable(source); err != nil {
		return err
	}
	return copyAtomic(ctx, source, destination, 0755)
}

func (unixFileOperator) WriteProtected(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if mode.Perm() == 0 {
		return errors.New("wire-connect: protected file mode is empty")
	}
	if err := ensureTrustedParent(filepath.Dir(path)); err != nil {
		return err
	}
	return writeAtomic(ctx, path, data, mode.Perm())
}

func (unixFileOperator) RemoveFile(ctx context.Context, path string) error {
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
	if err := os.Remove(path); err != nil {
		return err
	}
	return nil
}

func (unixFileOperator) RemoveDir(ctx context.Context, path string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateInstallDir(path); err != nil {
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
	// RemoveAll removes symlinks as directory entries and does not traverse
	// them.  The package root and service-name directory have already been
	// checked above, so this only removes package-owned files.
	return os.RemoveAll(path)
}

func validateUnixStateDir(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("wire-connect: state directory %q must be absolute", path)
	}
	path = filepath.Clean(path)
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("wire-connect: state directory %q must already exist; create it as root-owned mode 0700 before installing the service", path)
	}
	if err != nil {
		return fmt.Errorf("wire-connect: inspect state directory %q: %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("wire-connect: state directory %q must be a real directory", path)
	}
	if err := requireRootOwner(st, path); err != nil {
		return err
	}
	if st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("wire-connect: state directory %q must be mode 0700 and inaccessible to other users", path)
	}

	// A private leaf is insufficient when an untrusted user can replace one of
	// its parent directories.  Check every existing ancestor up to /.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		parentInfo, err := os.Lstat(parent)
		if err != nil {
			return fmt.Errorf("wire-connect: inspect state directory parent %q: %w", parent, err)
		}
		if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
			return fmt.Errorf("wire-connect: state directory parent %q must be a real directory", parent)
		}
		if err := requireRootOwner(parentInfo, parent); err != nil {
			return err
		}
		if parentInfo.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("wire-connect: state directory parent %q is writable by a non-root user", parent)
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return nil
}

func requireRootOwner(st os.FileInfo, path string) error {
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("wire-connect: inspect owner of %q: unsupported filesystem metadata", path)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("wire-connect: state directory %q must be owned by root (uid 0), got uid %d", path, stat.Uid)
	}
	return nil
}

func validateSourceExecutable(path string) error {
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
	if st.Mode()&0111 == 0 {
		return fmt.Errorf("wire-connect: executable %q is not executable", path)
	}
	return nil
}

func validateInstallDir(path string) error {
	cleanRoot := filepath.Clean(unixInstallRoot)
	cleanPath := filepath.Clean(path)
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || rel == "." || rel == "" || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("wire-connect: refusing to remove path outside the package installation root: %q", path)
	}
	if _, err := normalizeName(filepath.Base(cleanPath)); err != nil {
		return fmt.Errorf("wire-connect: refusing to remove invalid package installation %q", path)
	}
	return nil
}

func ensureSecureInstallParent(path string) error {
	cleanRoot := filepath.Clean(unixInstallRoot)
	cleanPath := filepath.Clean(path)
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q is outside the package installation root", path)
	}
	if err := checkTrustedAncestors(filepath.Dir(cleanRoot)); err != nil {
		return err
	}
	base := filepath.Dir(cleanRoot)
	relativeToBase, err := filepath.Rel(base, cleanPath)
	if err != nil || filepath.IsAbs(relativeToBase) || relativeToBase == ".." || strings.HasPrefix(relativeToBase, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q is outside the package installation root", path)
	}
	current := base
	for _, part := range strings.Split(relativeToBase, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		created := false
		st, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0755); err != nil {
				return err
			}
			created = true
			st, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("%q is not a real directory", current)
		}
		if err := requireRootOwner(st, current); err != nil {
			return err
		}
		if st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("%q is writable by a non-root user", current)
		}
		if created {
			if err := os.Chmod(current, 0755); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkTrustedAncestors(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return errors.New("directory path must be absolute")
	}
	for current := clean; ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect trusted directory %q: %w", current, err)
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("trusted directory %q is not a real directory", current)
		}
		if err := requireRootOwner(st, current); err != nil {
			return err
		}
		if st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("trusted directory %q is writable by a non-root user", current)
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

func ensureTrustedParent(path string) error {
	if err := checkTrustedAncestors(path); err != nil {
		return fmt.Errorf("wire-connect: service record directory: %w", err)
	}
	return nil
}

func copyAtomic(ctx context.Context, source, destination string, mode os.FileMode) error {
	src, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open executable source: %w", err)
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
		return fmt.Errorf("create protected executable temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return fmt.Errorf("copy executable: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync executable: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close executable: %w", err)
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return fmt.Errorf("install protected executable: %w", err)
	}
	return syncDirectory(filepath.Dir(destination))
}

func writeAtomic(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return fmt.Errorf("wire-connect: refusing to replace non-regular service record %q", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wire-connect-*.tmp")
	if err != nil {
		return fmt.Errorf("create service record temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write service record: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync service record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close service record: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("install service record: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func requireUnixRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("wire-connect: service installation requires root; rerun with sudo or as root")
	}
	return nil
}
