//go:build (linux && (amd64 || arm64)) || (darwin && arm64)

package netsetup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Keep helper files in the same root used by the existing connect service,
// but use a hash-derived name so one Unix login cannot collide with another.
var unixInstallRoot = "/usr/local/libexec/wire-connect"

type unixCommandRunner interface {
	Run(context.Context, string, ...string) error
	Output(context.Context, string, ...string) ([]byte, error)
}

type nativeUnixCommandRunner struct{}

func (nativeUnixCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	_, err := (nativeUnixCommandRunner{}).Output(ctx, name, args...)
	return err
}

func (nativeUnixCommandRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail != "" {
			return out, fmt.Errorf("run %s: %w: %s", formatUnixCommand(name, args), err, detail)
		}
		return out, fmt.Errorf("run %s: %w", formatUnixCommand(name, args), err)
	}
	return out, nil
}

func formatUnixCommand(name string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, name)
	for _, arg := range args {
		parts = append(parts, fmt.Sprintf("%q", arg))
	}
	return strings.Join(parts, " ")
}

var unixCommands unixCommandRunner = nativeUnixCommandRunner{}

func runUnixCommand(ctx context.Context, name string, args ...string) error {
	if unixCommands == nil {
		return errors.New("wire-connect: nil Unix command runner")
	}
	return unixCommands.Run(ctx, name, args...)
}

func outputUnixCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if unixCommands == nil {
		return nil, errors.New("wire-connect: nil Unix command runner")
	}
	return unixCommands.Output(ctx, name, args...)
}

// unixOwnerCheck is injectable for filesystem-policy tests. Production always
// requires uid 0 for every existing ancestor and installed object.
var unixOwnerCheck = requireUnixOwner

func requireUnixOwner(st os.FileInfo, path string) error {
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("wire-connect: inspect owner of %q: unsupported filesystem metadata", path)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("wire-connect: protected helper path %q must be owned by root (uid 0), got uid %d", path, stat.Uid)
	}
	return nil
}

func helperDir(name string) string { return filepath.Join(unixInstallRoot, name) }

func helperExecutable(name string) string { return filepath.Join(helperDir(name), "wirectl-connect") }

func helperUnitName(name string) string { return "wire-connect-" + name }

func ensureUnixInstallParent(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("wire-connect: protected helper path %q must be absolute", path)
	}
	clean := filepath.Clean(path)
	root := filepath.Clean(unixInstallRoot)
	rel, err := filepath.Rel(root, clean)
	if err != nil || rel == "." || rel == "" || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("wire-connect: protected helper path %q is outside installation root", path)
	}

	// Walk existing ancestors first. This prevents creating a protected-looking
	// leaf below a symlink or a directory writable by an untrusted user.
	missing := []string{}
	for current := clean; ; current = filepath.Dir(current) {
		st, statErr := os.Lstat(current)
		if statErr == nil {
			if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
				return fmt.Errorf("wire-connect: protected helper parent %q must be a real directory", current)
			}
			if err := unixOwnerCheck(st, current); err != nil {
				return err
			}
			if st.Mode().Perm()&0022 != 0 {
				return fmt.Errorf("wire-connect: protected helper parent %q is writable by a non-root user", current)
			}
			if err := checkUnixAncestors(filepath.Dir(current)); err != nil {
				return err
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("wire-connect: inspect protected helper parent %q: %w", current, statErr)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return fmt.Errorf("wire-connect: protected helper path %q has no existing root", path)
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		current := missing[i]
		if err := os.Mkdir(current, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("wire-connect: create protected helper directory %q: %w", current, err)
		}
		st, statErr := os.Lstat(current)
		if statErr != nil {
			return fmt.Errorf("wire-connect: inspect protected helper directory %q: %w", current, statErr)
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("wire-connect: protected helper directory %q is not a real directory", current)
		}
		if err := unixOwnerCheck(st, current); err != nil {
			return err
		}
		if st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("wire-connect: protected helper directory %q is writable by a non-root user", current)
		}
	}
	return nil
}

func checkUnixAncestors(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("wire-connect: inspect protected helper ancestor %q: %w", current, err)
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("wire-connect: protected helper ancestor %q must be a real directory", current)
		}
		if err := unixOwnerCheck(st, current); err != nil {
			return err
		}
		if st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("wire-connect: protected helper ancestor %q is writable by a non-root user", current)
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

func validateHelperDestination(path string, expectedDir string) error {
	clean := filepath.Clean(path)
	if filepath.Dir(clean) != filepath.Clean(expectedDir) {
		return fmt.Errorf("wire-connect: helper destination %q is outside its package directory", path)
	}
	if st, err := os.Lstat(clean); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return fmt.Errorf("wire-connect: refusing to replace non-regular helper file %q", path)
		}
		if err := unixOwnerCheck(st, clean); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("wire-connect: inspect helper destination %q: %w", path, err)
	}
	return nil
}

func copyUnixProtected(ctx context.Context, source, destination string) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateUnixSource(source, true); err != nil {
		return err
	}
	if err := ensureUnixInstallParent(filepath.Dir(destination)); err != nil {
		return err
	}
	if err := validateHelperDestination(destination, filepath.Dir(destination)); err != nil {
		return err
	}
	src, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("wire-connect: open helper source %q: %w", source, err)
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".wire-connect-helper-*.tmp")
	if err != nil {
		return fmt.Errorf("wire-connect: create protected helper temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0755); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, src); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: copy helper executable: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: sync helper executable: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("wire-connect: close helper executable: %w", err)
	}
	if err := unixOwnerCheckFile(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return fmt.Errorf("wire-connect: install protected helper executable: %w", err)
	}
	return syncUnixDirectory(filepath.Dir(destination))
}

func validateUnixSource(path string, executable bool) error {
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
	if executable && st.Mode()&0111 == 0 {
		return fmt.Errorf("wire-connect: helper source %q is not executable", path)
	}
	return nil
}

func unixOwnerCheckFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect installed helper file %q: %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: installed helper file %q is not a regular file", path)
	}
	return unixOwnerCheck(st, path)
}

func writeUnixProtected(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if mode.Perm() == 0 {
		return errors.New("wire-connect: protected helper record mode is empty")
	}
	if err := ensureUnixInstallParent(filepath.Dir(path)); err != nil {
		return err
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return fmt.Errorf("wire-connect: refusing to replace non-regular helper record %q", path)
		}
		if err := unixOwnerCheck(st, path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wire-connect-helper-*.tmp")
	if err != nil {
		return fmt.Errorf("wire-connect: create helper record temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: write helper record: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: sync helper record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := unixOwnerCheckFile(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("wire-connect: install helper record: %w", err)
	}
	return syncUnixDirectory(filepath.Dir(path))
}

// writeUnixRecordProtected is used for native service records outside the
// package executable root (systemd units and LaunchDaemon plists). Their
// parents must already be administrator-owned; unlike the package root, this
// function never creates an arbitrary directory tree.
func writeUnixRecordProtected(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if mode.Perm() == 0 {
		return errors.New("wire-connect: protected helper record mode is empty")
	}
	parent := filepath.Dir(filepath.Clean(path))
	if err := checkUnixAncestors(parent); err != nil {
		return err
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return fmt.Errorf("wire-connect: refusing to replace non-regular helper record %q", path)
		}
		if err := unixOwnerCheck(st, path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".wire-connect-helper-*.tmp")
	if err != nil {
		return fmt.Errorf("wire-connect: create helper record temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: write helper record: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wire-connect: sync helper record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := unixOwnerCheckFile(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("wire-connect: install helper record: %w", err)
	}
	return syncUnixDirectory(parent)
}

func syncUnixDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func removeUnixInstalledDir(path string) error {
	root := filepath.Clean(unixInstallRoot)
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(root, clean)
	if err != nil || rel == "." || rel == "" || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("wire-connect: refusing to remove helper path outside installation root: %q", path)
	}
	if _, err := normalizeHelperName(filepath.Base(clean)); err != nil {
		return err
	}
	if err := checkUnixAncestors(root); err != nil {
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
	if err := unixOwnerCheck(st, clean); err != nil {
		return err
	}
	return os.RemoveAll(clean)
}

func removeUnixRecord(path, parent string) error {
	cleanParent := filepath.Clean(parent)
	clean := filepath.Clean(path)
	if filepath.Dir(clean) != cleanParent {
		return fmt.Errorf("wire-connect: refusing to remove record outside %q", cleanParent)
	}
	if err := checkUnixAncestors(cleanParent); err != nil {
		return err
	}
	st, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: refusing to remove non-regular helper record %q", clean)
	}
	if err := unixOwnerCheck(st, clean); err != nil {
		return err
	}
	return os.Remove(clean)
}
