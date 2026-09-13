//go:build windows

package update

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const (
	// applyUpdateCommand is deliberately not part of the public CLI help.  It
	// is the one handoff entry point used by the new image after the old image
	// has exited.
	applyUpdateCommand = "__apply-update"
	// cleanupUpdateCommand is run by the newly installed image.  A Windows
	// process cannot unlink its own executable, so the short-lived target
	// process removes the helper and transaction after refresh completes.
	cleanupUpdateCommand = "__cleanup-update"

	// Version 2 persists every rollback path before the helper starts.  This
	// lets a later handoff resume or restore files after a helper crash.
	windowsUpdateTransactionVersion = 2
	windowsUpdateWaitTimeout        = 2 * time.Minute
	windowsUpdateRenameWait         = 30 * time.Second
	windowsUpdateRenameInterval     = 100 * time.Millisecond
	windowsUpdateMaxTransaction     = 64 << 10
)

type windowsRuntimeUpdate struct {
	Source string `json:"source"`
	Target string `json:"target"`
	SHA256 string `json:"sha256"`
	Backup string `json:"backup"`
}

type windowsUpdateTransaction struct {
	Version         int                    `json:"version"`
	ParentPID       uint32                 `json:"parent_pid"`
	ParentStart     uint64                 `json:"parent_start"`
	Source          string                 `json:"source"`
	Target          string                 `json:"target"`
	SHA256          string                 `json:"sha256"`
	TargetBackup    string                 `json:"target_backup"`
	Helper          string                 `json:"helper"`
	HelperSHA256    string                 `json:"helper_sha256"`
	RefreshStateDir string                 `json:"refresh_state_dir,omitempty"`
	Runtime         []windowsRuntimeUpdate `json:"runtime"`
}

type windowsReplacementFile struct {
	source string
	target string
	digest string
	backup string
}

type windowsRollbackFile struct {
	file       windowsReplacementFile
	backup     string
	oldExisted bool
	installed  bool
}

func runtimeFilesMatch(executable string, packageFiles extractedPackage) (bool, error) {
	dir := filepath.Dir(executable)
	for _, item := range []struct {
		name string
		data []byte
	}{
		{name: "wintun.dll", data: packageFiles.Wintun},
		{name: "WINTUN-LICENSE.txt", data: packageFiles.WintunLicense},
	} {
		path := filepath.Join(dir, item.name)
		st, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("wire-connect: inspect Windows runtime %q: %w", path, err)
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return false, fmt.Errorf("wire-connect: Windows runtime %q must be a regular file, not a symlink", path)
		}
		got, err := digestFile(path, DefaultMaxExecutableBytes)
		if err != nil {
			return false, fmt.Errorf("wire-connect: read Windows runtime %q: %w", path, err)
		}
		if got != digestBytes(item.data) {
			return false, nil
		}
	}
	return true, nil
}

// installStagedExecutable cannot replace the image which is currently
// running on Windows.  It copies the verified new image to a separate
// helper image, writes a private transaction, and starts that helper.  The
// caller must return so the helper can wait for this process to exit.
func installStagedExecutable(ctx context.Context, source, target, digest string, packageFiles extractedPackage, refreshStateDir string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if refreshStateDir != "" {
		absolute, err := filepath.Abs(refreshStateDir)
		if err != nil {
			return false, fmt.Errorf("wire-connect: resolve Windows refresh state directory: %w", err)
		}
		refreshStateDir = filepath.Clean(absolute)
	}
	if len(packageFiles.Wintun) == 0 || len(packageFiles.WintunLicense) == 0 {
		return false, fmt.Errorf("%w: Windows update is missing Wintun runtime files", ErrInvalidRelease)
	}
	dir := filepath.Dir(target)
	if !sameWindowsPath(filepath.Dir(source), dir) {
		return false, fmt.Errorf("%w: Windows update staging files must share the executable directory", ErrInvalidRelease)
	}
	if err := validateRegularNoSymlink(source); err != nil {
		return false, fmt.Errorf("wire-connect: validate staged Windows executable: %w", err)
	}
	expectedDigest, err := parsePlainSHA256(digest)
	if err != nil {
		return false, fmt.Errorf("%w: invalid staged Windows executable digest", ErrInvalidRelease)
	}
	actualDigest, err := digestFile(source, DefaultMaxExecutableBytes)
	if err != nil {
		return false, fmt.Errorf("wire-connect: hash staged Windows executable: %w", err)
	}
	if actualDigest != expectedDigest {
		return false, fmt.Errorf("%w: staged Windows executable digest mismatch", ErrInvalidRelease)
	}
	if err := validateInstallTarget(target); err != nil {
		return false, err
	}
	if err := validateWindowsRuntimeTarget(filepath.Join(dir, "wintun.dll")); err != nil {
		return false, err
	}
	if err := validateWindowsRuntimeTarget(filepath.Join(dir, "WINTUN-LICENSE.txt")); err != nil {
		return false, err
	}

	runtimeFiles := []windowsReplacementFile{}
	var helper string
	cleanupStaged := true
	defer func() {
		if cleanupStaged {
			cleanupWindowsReplacement(source, runtimeFiles, helper)
		}
	}()
	for _, item := range []struct {
		name string
		data []byte
	}{
		{name: "wintun.dll", data: packageFiles.Wintun},
		{name: "WINTUN-LICENSE.txt", data: packageFiles.WintunLicense},
	} {
		path := filepath.Join(dir, item.name)
		mode, err := windowsReplacementMode(path, 0644)
		if err != nil {
			return false, err
		}
		runtimeSource, err := stageWindowsFile(ctx, dir, ".wire-connect-runtime-*", item.data, mode)
		if err != nil {
			return false, err
		}
		runtimeFiles = append(runtimeFiles, windowsReplacementFile{
			source: runtimeSource,
			target: path,
			digest: digestBytes(item.data),
		})
	}
	targetBackup, err := reserveWindowsBackupPath(target)
	if err != nil {
		return false, err
	}
	cleanupBackups := true
	defer func() {
		if cleanupBackups {
			_ = removeWindowsRegularFile(targetBackup)
			for _, item := range runtimeFiles {
				_ = removeWindowsRegularFile(item.backup)
			}
		}
	}()
	for i := range runtimeFiles {
		runtimeFiles[i].backup, err = reserveWindowsBackupPath(runtimeFiles[i].target)
		if err != nil {
			return false, err
		}
	}

	// The helper must be a separate file.  Launching the target itself would
	// leave the helper holding the target image open and make its own rename
	// impossible.  Copying the new image also makes updates from older
	// releases work: only the downloaded image needs to know this command.
	st, err := os.Lstat(source)
	if err != nil {
		cleanupWindowsReplacement(source, runtimeFiles, "")
		return false, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return false, fmt.Errorf("wire-connect: staged Windows executable must be a regular file")
	}
	helper, err = stageWindowsFile(ctx, dir, ".wire-connect-update-helper-*", packageFiles.Executable, st.Mode().Perm())
	if err != nil {
		return false, err
	}

	parentStart, err := currentProcessStartTime()
	if err != nil {
		return false, fmt.Errorf("wire-connect: identify current process for Windows update: %w", err)
	}
	tx := windowsUpdateTransaction{
		Version:         windowsUpdateTransactionVersion,
		ParentPID:       uint32(os.Getpid()),
		ParentStart:     parentStart,
		Source:          source,
		Target:          target,
		SHA256:          digest,
		TargetBackup:    targetBackup,
		Helper:          helper,
		HelperSHA256:    digestBytes(packageFiles.Executable),
		RefreshStateDir: refreshStateDir,
	}
	for _, item := range runtimeFiles {
		tx.Runtime = append(tx.Runtime, windowsRuntimeUpdate{Source: item.source, Target: item.target, SHA256: item.digest, Backup: item.backup})
	}
	txPath, err := writeWindowsTransaction(ctx, dir, tx)
	if err != nil {
		return false, err
	}
	if err := startWindowsUpdateHelper(ctx, helper, txPath); err != nil {
		_ = removeWindowsStagingFile(txPath, ".wire-connect-update-transaction-")
		return false, err
	}
	cleanupStaged = false
	cleanupBackups = false
	return true, nil
}

func validateWindowsRuntimeTarget(name string) error {
	if !filepath.IsAbs(name) {
		return fmt.Errorf("%w: Windows runtime path must be absolute", ErrInvalidRelease)
	}
	st, err := os.Lstat(filepath.Clean(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("wire-connect: inspect Windows runtime %q: %w", name, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: Windows runtime %q must be a regular file, not a symlink", name)
	}
	return nil
}

func windowsReplacementMode(name string, fallback os.FileMode) (os.FileMode, error) {
	st, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return fallback, nil
	}
	if err != nil {
		return 0, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return 0, fmt.Errorf("wire-connect: Windows runtime %q must be a regular file, not a symlink", name)
	}
	return st.Mode().Perm(), nil
}

func stageWindowsFile(ctx context.Context, dir, pattern string, data []byte, mode os.FileMode) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("wire-connect: create Windows update staging file: %w", err)
	}
	name := f.Name()
	remove := true
	defer func() {
		if remove {
			_ = removeWindowsStagingFile(name, strings.TrimSuffix(pattern, "*"))
		}
	}()
	if err := f.Chmod(mode.Perm()); err != nil {
		_ = f.Close()
		return "", err
	}
	if _, err := f.Write(data); err != nil {
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
	remove = false
	return name, nil
}

func writeWindowsTransaction(ctx context.Context, dir string, tx windowsUpdateTransaction) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	b, err := json.Marshal(tx)
	if err != nil {
		return "", fmt.Errorf("wire-connect: encode Windows update transaction: %w", err)
	}
	if len(b) > windowsUpdateMaxTransaction {
		return "", fmt.Errorf("%w: Windows update transaction is too large", ErrInvalidRelease)
	}
	f, err := os.CreateTemp(dir, ".wire-connect-update-transaction-*")
	if err != nil {
		return "", fmt.Errorf("wire-connect: create Windows update transaction: %w", err)
	}
	name := f.Name()
	remove := true
	defer func() {
		if remove {
			_ = removeWindowsStagingFile(name, ".wire-connect-update-transaction-")
		}
	}()
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return "", err
	}
	if _, err := f.Write(b); err != nil {
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
	remove = false
	return name, nil
}

func startWindowsUpdateHelper(ctx context.Context, helper, transaction string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(helper, applyUpdateCommand, "--transaction", transaction)
	cmd.Dir = filepath.Dir(helper)
	cmd.Stdin = nil
	// Keep failure diagnostics visible to the terminal that requested the
	// update.  The helper is detached from the caller's wait lifecycle, but it
	// remains in the same console when one exists.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("wire-connect: start Windows update helper: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("wire-connect: detach Windows update helper: %w", err)
	}
	return nil
}

func cleanupWindowsReplacement(source string, runtimeFiles []windowsReplacementFile, helper string) {
	_ = removeWindowsStagingFile(source, ".wire-connect-executable-")
	for _, item := range runtimeFiles {
		_ = removeWindowsStagingFile(item.source, ".wire-connect-runtime-")
	}
	if helper != "" {
		_ = removeWindowsStagingFile(helper, ".wire-connect-update-helper-")
	}
}

// Apply is called only by the hidden __apply-update CLI entry point.  It is
// exported so the CLI can keep command parsing separate from this package;
// ordinary users should use Run instead.
func Apply(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil {
		return errors.New("wire-connect: nil context")
	}
	f := flag.NewFlagSet(applyUpdateCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	transaction := f.String("transaction", "", "private update transaction")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *transaction == "" {
		return errors.New("usage: __apply-update --transaction FILE")
	}
	return applyWindowsTransaction(ctx, *transaction, out)
}

func applyWindowsTransaction(ctx context.Context, transaction string, out io.Writer) error {
	if out == nil {
		out = io.Discard
	}
	txPath, err := filepath.Abs(transaction)
	if err != nil {
		return err
	}
	txPath = filepath.Clean(txPath)
	if !strings.HasPrefix(filepath.Base(txPath), ".wire-connect-update-transaction-") {
		return fmt.Errorf("%w: invalid Windows update transaction path", ErrInvalidRelease)
	}
	b, err := readRegularFile(txPath, windowsUpdateMaxTransaction)
	if err != nil {
		return fmt.Errorf("wire-connect: read Windows update transaction: %w", err)
	}
	var tx windowsUpdateTransaction
	if err := json.Unmarshal(b, &tx); err != nil {
		return fmt.Errorf("%w: decode Windows update transaction: %v", ErrInvalidRelease, err)
	}
	if err := validateWindowsTransaction(tx, txPath); err != nil {
		return err
	}
	if err := validateWindowsHelperImage(tx); err != nil {
		return err
	}
	if err := waitForWindowsParent(ctx, tx.ParentPID, tx.ParentStart); err != nil {
		return err
	}
	if err := validateWindowsTransactionSources(tx); err != nil {
		return err
	}
	files := []windowsReplacementFile{{source: tx.Source, target: tx.Target, digest: tx.SHA256, backup: tx.TargetBackup}}
	for _, item := range tx.Runtime {
		files = append(files, windowsReplacementFile{source: item.Source, target: item.Target, digest: item.SHA256, backup: item.Backup})
	}
	if err := applyWindowsFiles(ctx, files); err != nil {
		return err
	}
	// The helper is still running from tx.Helper and therefore cannot remove
	// that image on Windows.  Remove the staging sources here, then ask the
	// newly installed target to remove the helper and transaction after it has
	// refreshed background components.
	cleanupWindowsReplacement(tx.Source, files[1:], "")
	refreshErr := runWindowsRefresh(ctx, tx.Target, tx.RefreshStateDir, out)
	helperStart, helperStartErr := currentProcessStartTime()
	cleanupErr := helperStartErr
	if cleanupErr == nil {
		cleanupErr = startWindowsCleanup(context.Background(), tx.Target, txPath, uint32(os.Getpid()), helperStart)
	}
	if refreshErr != nil && cleanupErr != nil {
		return errors.Join(refreshErr, cleanupErr)
	}
	if refreshErr != nil {
		return refreshErr
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	fmt.Fprintln(out, "Update complete.")
	return nil
}

// Cleanup is called by the newly installed image to finish a Windows update
// handoff.  It intentionally accepts only a transaction path; all paths to
// delete are recovered from and constrained by that authenticated transaction.
func Cleanup(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil {
		return errors.New("wire-connect: nil context")
	}
	f := flag.NewFlagSet(cleanupUpdateCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	transaction := f.String("transaction", "", "private update transaction")
	waitPID := f.Uint("wait-pid", 0, "helper process ID to wait for")
	waitStart := f.Uint64("wait-start", 0, "helper process creation time")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *transaction == "" {
		return errors.New("usage: __cleanup-update --transaction FILE")
	}
	if (*waitPID == 0) != (*waitStart == 0) || uint64(*waitPID) > uint64(^uint32(0)) {
		return fmt.Errorf("%w: invalid Windows cleanup wait identity", ErrInvalidRelease)
	}
	return cleanupWindowsTransaction(ctx, *transaction, uint32(*waitPID), *waitStart)
}

func startWindowsCleanup(ctx context.Context, target, transaction string, waitPID uint32, waitStart uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	args := []string{cleanupUpdateCommand, "--transaction", transaction, "--wait-pid", strconv.FormatUint(uint64(waitPID), 10), "--wait-start", strconv.FormatUint(waitStart, 10)}
	cmd := exec.Command(target, args...)
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("wire-connect: start Windows update cleanup: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("wire-connect: detach Windows update cleanup: %w", err)
	}
	return nil
}

func cleanupWindowsTransaction(ctx context.Context, transaction string, waitPID uint32, waitStart uint64) error {
	txPath, err := filepath.Abs(transaction)
	if err != nil {
		return err
	}
	txPath = filepath.Clean(txPath)
	if !strings.HasPrefix(filepath.Base(txPath), ".wire-connect-update-transaction-") {
		return fmt.Errorf("%w: invalid Windows update transaction path", ErrInvalidRelease)
	}
	b, err := readRegularFile(txPath, windowsUpdateMaxTransaction)
	if err != nil {
		return fmt.Errorf("wire-connect: read Windows update transaction: %w", err)
	}
	var tx windowsUpdateTransaction
	if err := json.Unmarshal(b, &tx); err != nil {
		return fmt.Errorf("%w: decode Windows update transaction: %v", ErrInvalidRelease, err)
	}
	if err := validateWindowsTransaction(tx, txPath); err != nil {
		return err
	}
	if waitPID != 0 {
		if err := waitForWindowsParent(ctx, waitPID, waitStart); err != nil {
			return err
		}
	}
	current, err := executablePath("")
	if err != nil {
		return err
	}
	if !sameWindowsPath(current, tx.Target) {
		return fmt.Errorf("%w: cleanup executable does not match Windows update target", ErrInvalidRelease)
	}
	if err := removeWindowsStagingFile(tx.Source, ".wire-connect-executable-"); err != nil {
		return err
	}
	for _, item := range tx.Runtime {
		if err := removeWindowsStagingFile(item.Source, ".wire-connect-runtime-"); err != nil {
			return err
		}
	}
	if err := removeWindowsStagingFile(tx.Helper, ".wire-connect-update-helper-"); err != nil {
		return err
	}
	if err := removeWindowsStagingFile(txPath, ".wire-connect-update-transaction-"); err != nil {
		return err
	}
	return nil
}

func removeWindowsStagingFile(name, prefix string) error {
	if name == "" || !strings.HasPrefix(filepath.Base(name), prefix) {
		return fmt.Errorf("%w: invalid Windows update cleanup path", ErrInvalidRelease)
	}
	st, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: refusing to remove non-regular Windows update file %q", name)
	}
	return removeWindowsRegularFile(name)
}

func removeWindowsRegularFile(name string) error {
	st, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: refusing to remove non-regular Windows file %q", name)
	}
	if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func validateWindowsTransaction(tx windowsUpdateTransaction, txPath string) error {
	if tx.Version != windowsUpdateTransactionVersion || tx.ParentPID == 0 || tx.ParentStart == 0 {
		return fmt.Errorf("%w: unsupported Windows update transaction", ErrInvalidRelease)
	}
	if tx.Source == "" || tx.Target == "" || tx.TargetBackup == "" || tx.Helper == "" || tx.SHA256 == "" || tx.HelperSHA256 == "" {
		return fmt.Errorf("%w: incomplete Windows update transaction", ErrInvalidRelease)
	}
	target, err := filepath.Abs(tx.Target)
	if err != nil {
		return err
	}
	target = filepath.Clean(target)
	source, err := filepath.Abs(tx.Source)
	if err != nil {
		return err
	}
	helper, err := filepath.Abs(tx.Helper)
	if err != nil {
		return err
	}
	transactionDir := filepath.Dir(txPath)
	if !sameWindowsPath(filepath.Dir(source), transactionDir) || !sameWindowsPath(filepath.Dir(target), transactionDir) || !sameWindowsPath(filepath.Dir(helper), transactionDir) {
		return fmt.Errorf("%w: Windows update files must share one protected directory", ErrInvalidRelease)
	}
	if sameWindowsPath(source, target) || sameWindowsPath(helper, target) || sameWindowsPath(source, helper) {
		return fmt.Errorf("%w: Windows update transaction aliases its files", ErrInvalidRelease)
	}
	if !strings.HasPrefix(filepath.Base(source), ".wire-connect-executable-") || !strings.HasPrefix(filepath.Base(helper), ".wire-connect-update-helper-") {
		return fmt.Errorf("%w: invalid Windows update staging file", ErrInvalidRelease)
	}
	if len(tx.Runtime) != 2 {
		return fmt.Errorf("%w: Windows update transaction must contain Wintun and license", ErrInvalidRelease)
	}
	targetBackup, err := filepath.Abs(tx.TargetBackup)
	if err != nil {
		return err
	}
	if !sameWindowsPath(filepath.Dir(targetBackup), transactionDir) || !strings.HasPrefix(filepath.Base(targetBackup), ".wire-connect-old-") || sameWindowsPath(targetBackup, target) || sameWindowsPath(targetBackup, source) || sameWindowsPath(targetBackup, helper) {
		return fmt.Errorf("%w: invalid Windows executable rollback path", ErrInvalidRelease)
	}
	if err := validateOptionalWindowsBackup(targetBackup); err != nil {
		return err
	}
	seenBackups := map[string]bool{strings.ToLower(targetBackup): true}
	wantRuntime := map[string]bool{
		filepath.Join(transactionDir, "wintun.dll"):         false,
		filepath.Join(transactionDir, "WINTUN-LICENSE.txt"): false,
	}
	for _, item := range tx.Runtime {
		if item.Source == "" || item.Target == "" || item.SHA256 == "" || item.Backup == "" {
			return fmt.Errorf("%w: incomplete Windows runtime update", ErrInvalidRelease)
		}
		sourcePath, err := filepath.Abs(item.Source)
		if err != nil {
			return err
		}
		targetPath, err := filepath.Abs(item.Target)
		if err != nil {
			return err
		}
		if !sameWindowsPath(filepath.Dir(sourcePath), transactionDir) || !sameWindowsPath(filepath.Dir(targetPath), transactionDir) {
			return fmt.Errorf("%w: Windows runtime files must share one protected directory", ErrInvalidRelease)
		}
		if !strings.HasPrefix(filepath.Base(sourcePath), ".wire-connect-runtime-") {
			return fmt.Errorf("%w: invalid Windows runtime staging file", ErrInvalidRelease)
		}
		backupPath, err := filepath.Abs(item.Backup)
		if err != nil {
			return err
		}
		if !sameWindowsPath(filepath.Dir(backupPath), transactionDir) || !strings.HasPrefix(filepath.Base(backupPath), ".wire-connect-old-") || sameWindowsPath(backupPath, sourcePath) || sameWindowsPath(backupPath, targetPath) || sameWindowsPath(backupPath, source) || sameWindowsPath(backupPath, target) || sameWindowsPath(backupPath, helper) || seenBackups[strings.ToLower(backupPath)] {
			return fmt.Errorf("%w: invalid Windows runtime rollback path", ErrInvalidRelease)
		}
		if err := validateOptionalWindowsBackup(backupPath); err != nil {
			return err
		}
		seenBackups[strings.ToLower(backupPath)] = true
		for name := range wantRuntime {
			if sameWindowsPath(targetPath, name) {
				if wantRuntime[name] {
					return fmt.Errorf("%w: duplicate Windows runtime target", ErrInvalidRelease)
				}
				wantRuntime[name] = true
			}
		}
	}
	for name, found := range wantRuntime {
		if !found {
			return fmt.Errorf("%w: Windows update is missing runtime target %q", ErrInvalidRelease, name)
		}
	}
	return nil
}

func validateOptionalWindowsBackup(name string) error {
	st, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("wire-connect: inspect Windows rollback path %q: %w", name, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("wire-connect: Windows rollback path %q must be a regular file", name)
	}
	return nil
}

func validateWindowsHelperImage(tx windowsUpdateTransaction) error {
	if err := validateRegularNoSymlink(tx.Helper); err != nil {
		return fmt.Errorf("wire-connect: validate Windows update helper: %w", err)
	}
	digest, err := digestFile(tx.Helper, DefaultMaxExecutableBytes)
	if err != nil {
		return err
	}
	expected, err := parsePlainSHA256(tx.HelperSHA256)
	if err != nil || digest != expected {
		return fmt.Errorf("%w: Windows update helper digest mismatch", ErrInvalidRelease)
	}
	return nil
}

func validateWindowsTransactionSources(tx windowsUpdateTransaction) error {
	// A helper can be interrupted after the source has been renamed into its
	// target. In that state the source is intentionally gone, while the target
	// already has the authenticated digest. Validate the complete transaction
	// state instead of requiring every staging path to exist. The replacement
	// loop performs the same checks again immediately before each rename.
	files := make([]windowsReplacementFile, 0, 1+len(tx.Runtime))
	files = append(files, windowsReplacementFile{
		source: tx.Source,
		target: tx.Target,
		digest: tx.SHA256,
		backup: tx.TargetBackup,
	})
	for _, item := range tx.Runtime {
		files = append(files, windowsReplacementFile{
			source: item.Source,
			target: item.Target,
			digest: item.SHA256,
			backup: item.Backup,
		})
	}

	for i, file := range files {
		expected, err := parsePlainSHA256(file.digest)
		if err != nil {
			kind := "runtime"
			if i == 0 {
				kind = "executable"
			}
			return fmt.Errorf("%w: invalid staged Windows %s digest", ErrInvalidRelease, kind)
		}

		sourceExists, err := windowsRegularState(file.source)
		if err != nil {
			return fmt.Errorf("wire-connect: inspect staged Windows file %q: %w", file.source, err)
		}
		targetExists, err := windowsRegularState(file.target)
		if err != nil {
			return fmt.Errorf("wire-connect: inspect Windows replacement target %q: %w", file.target, err)
		}
		backupExists, err := windowsRegularState(file.backup)
		if err != nil {
			return fmt.Errorf("wire-connect: inspect Windows rollback path %q: %w", file.backup, err)
		}

		targetMatches := false
		if targetExists {
			targetDigest, digestErr := digestFile(file.target, DefaultMaxExecutableBytes)
			if digestErr != nil {
				return fmt.Errorf("wire-connect: hash Windows replacement target %q: %w", file.target, digestErr)
			}
			targetMatches = targetDigest == expected
		}

		if sourceExists {
			sourceDigest, digestErr := digestFile(file.source, DefaultMaxExecutableBytes)
			if digestErr != nil {
				return fmt.Errorf("wire-connect: hash staged Windows file %q: %w", file.source, digestErr)
			}
			if sourceDigest != expected {
				return fmt.Errorf("%w: staged Windows file %q digest mismatch", ErrInvalidRelease, file.source)
			}
		} else if !targetMatches {
			return fmt.Errorf("wire-connect: staged Windows file %q is missing and its target is not installed", file.source)
		}

		// A target plus a rollback backup is a valid interrupted handoff only
		// when the target is the new image. If it is still an unknown old image,
		// the backup cannot be distinguished from a stale or malicious file and
		// the helper must refuse to guess.
		if targetExists && backupExists && !targetMatches {
			return fmt.Errorf("%w: Windows target %q and rollback backup both exist with unexpected contents", ErrInvalidRelease, file.target)
		}

		// The executable was present when the transaction was created. If both
		// it and its backup disappeared, the helper cannot restore or complete
		// the handoff safely. Runtime files may legitimately be absent before
		// their first install, so this condition is specific to the executable.
		if i == 0 && !targetExists && !backupExists {
			return fmt.Errorf("wire-connect: Windows executable target and rollback backup are both missing")
		}
	}
	return nil
}

func currentProcessStartTime() (uint64, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime), nil
}

func waitForWindowsParent(ctx context.Context, pid uint32, expectedStart uint64) error {
	if pid == uint32(os.Getpid()) {
		return fmt.Errorf("%w: update helper cannot wait for itself", ErrInvalidRelease)
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("wire-connect: open original Windows process: %w", err)
	}
	defer windows.Close(handle)
	actualStart, err := processStartTime(handle)
	if err != nil {
		return fmt.Errorf("wire-connect: identify original Windows process: %w", err)
	}
	if actualStart != expectedStart {
		return fmt.Errorf("%w: original process identity changed", ErrInvalidRelease)
	}
	deadline := time.Now().Add(windowsUpdateWaitTimeout)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wire-connect: timed out waiting for the original process to exit")
		}
		state, err := windows.WaitForSingleObject(handle, 250)
		if err != nil {
			return fmt.Errorf("wire-connect: wait for original Windows process: %w", err)
		}
		if state == windows.WAIT_OBJECT_0 {
			return nil
		}
		if state != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("wire-connect: unexpected Windows process wait result 0x%x", state)
		}
	}
}

func processStartTime(handle windows.Handle) (uint64, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime), nil
}

func applyWindowsFiles(ctx context.Context, files []windowsReplacementFile) error {
	if len(files) == 0 {
		return fmt.Errorf("%w: no Windows update files", ErrInvalidRelease)
	}
	rollback := make([]windowsRollbackFile, 0, len(files))
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		targetExists, err := windowsRegularState(file.target)
		if err != nil {
			return err
		}
		backup := file.backup
		backupExists := false
		if backup != "" {
			if !strings.HasPrefix(filepath.Base(backup), ".wire-connect-old-") || !sameWindowsPath(filepath.Dir(backup), filepath.Dir(file.target)) {
				return fmt.Errorf("%w: invalid Windows rollback path", ErrInvalidRelease)
			}
			backupExists, err = windowsRegularState(backup)
			if err != nil {
				return err
			}
		} else {
			backup, backupExists, err = windowsBackupPath(file.target)
			if err != nil {
				return err
			}
		}
		if sameWindowsPath(file.target, files[0].target) {
			if err := validateUpdateDestinationSecurity(file.target); err != nil {
				return err
			}
			if targetExists {
				if err := validateInstallTarget(file.target); err != nil {
					return err
				}
			} else if !backupExists {
				return fmt.Errorf("wire-connect: Windows executable target disappeared before handoff")
			}
		} else if err := validateWindowsRuntimeTarget(file.target); err != nil {
			return err
		}
		targetMatches := false
		if targetExists {
			digest, digestErr := digestFile(file.target, DefaultMaxExecutableBytes)
			if digestErr != nil {
				return digestErr
			}
			expected, parseErr := parsePlainSHA256(file.digest)
			if parseErr != nil {
				return fmt.Errorf("%w: invalid Windows replacement digest", ErrInvalidRelease)
			}
			targetMatches = digest == expected
		}
		record := windowsRollbackFile{file: file, backup: backup, oldExisted: backupExists}
		rollback = append(rollback, record)
		if targetMatches {
			rollback[len(rollback)-1].installed = true
			continue
		}
		if targetExists && backupExists {
			return rollbackWindowsFiles(ctx, rollback, fmt.Errorf("wire-connect: Windows target %q and rollback backup both exist with unexpected contents", file.target))
		}
		sourceExists, sourceErr := windowsRegularState(file.source)
		if sourceErr != nil {
			return rollbackWindowsFiles(ctx, rollback, fmt.Errorf("wire-connect: inspect staged Windows file %q: %v", file.source, sourceErr))
		}
		if !sourceExists {
			return rollbackWindowsFiles(ctx, rollback, fmt.Errorf("wire-connect: staged Windows file %q is missing", file.source))
		}
		if targetExists && !backupExists {
			if err := renameWindowsWithRetry(ctx, file.target, backup); err != nil {
				return rollbackWindowsFiles(ctx, rollback, fmt.Errorf("%w: move existing Windows file %q: %v", ErrExecutableInUse, file.target, err))
			}
			rollback[len(rollback)-1].oldExisted = true
		}
		if err := renameWindowsWithRetry(ctx, file.source, file.target); err != nil {
			return rollbackWindowsFiles(ctx, rollback, fmt.Errorf("%w: install Windows file %q: %v", ErrExecutableInUse, file.target, err))
		}
		rollback[len(rollback)-1].installed = true
	}
	for _, record := range rollback {
		if record.backup != "" {
			if err := removeWindowsRegularFile(record.backup); err != nil {
				return fmt.Errorf("wire-connect: updated Windows file but could not remove rollback backup %q: %w", record.backup, err)
			}
		}
	}
	return nil
}

func windowsRegularState(name string) (bool, error) {
	st, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return false, fmt.Errorf("wire-connect: Windows update path %q must be a regular file, not a symlink", name)
	}
	return true, nil
}

func windowsBackupPath(target string) (string, bool, error) {
	st, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return "", false, fmt.Errorf("wire-connect: refusing to replace non-regular Windows file %q", target)
	}
	name, err := reserveWindowsBackupPath(target)
	if err != nil {
		return "", false, err
	}
	return name, true, nil
}

func reserveWindowsBackupPath(target string) (string, error) {
	st, err := os.Lstat(target)
	if err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return "", fmt.Errorf("wire-connect: refusing to replace non-regular Windows file %q", target)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(target), ".wire-connect-old-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		_ = removeWindowsRegularFile(name)
		return "", err
	}
	if err := removeWindowsRegularFile(name); err != nil {
		return "", err
	}
	return name, nil
}

func rollbackWindowsFiles(ctx context.Context, records []windowsRollbackFile, cause error) error {
	var rollbackErr error
	for i := len(records) - 1; i >= 0; i-- {
		record := records[i]
		if record.installed {
			if err := validateRegularNoSymlink(record.file.target); err == nil {
				if removeErr := removeWindowsRegularFile(record.file.target); removeErr != nil {
					rollbackErr = errors.Join(rollbackErr, removeErr)
				}
			} else {
				rollbackErr = errors.Join(rollbackErr, err)
			}
		}
		if record.oldExisted {
			if err := validateRegularNoSymlink(record.backup); err != nil {
				rollbackErr = errors.Join(rollbackErr, err)
			} else if err := renameWindowsWithRetry(ctx, record.backup, record.file.target); err != nil {
				rollbackErr = errors.Join(rollbackErr, err)
			}
		} else if record.backup != "" {
			_ = removeWindowsRegularFile(record.backup)
		}
	}
	if rollbackErr != nil {
		return fmt.Errorf("%w: %v (rollback failed: %v)", ErrUpdateRollback, cause, rollbackErr)
	}
	return cause
}

func renameWindowsWithRetry(ctx context.Context, oldPath, newPath string) error {
	deadline := time.Now().Add(windowsUpdateRenameWait)
	var last error
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.Rename(oldPath, newPath); err == nil {
			return nil
		} else {
			last = err
		}
		if time.Now().After(deadline) {
			return last
		}
		timer := time.NewTimer(windowsUpdateRenameInterval)
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

func runWindowsRefresh(ctx context.Context, target, refreshStateDir string, out io.Writer) error {
	if out == nil {
		out = io.Discard
	}
	args := []string{"__refresh-update"}
	if refreshStateDir != "" {
		args = append(args, "--state-dir", refreshStateDir)
	}
	cmd := exec.CommandContext(ctx, target, args...)
	cmd.Stdin = nil
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wire-connect: client updated, but background components need attention: %w", err)
	}
	return nil
}

func sameWindowsPath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
