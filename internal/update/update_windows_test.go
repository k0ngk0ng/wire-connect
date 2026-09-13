//go:build windows && amd64

package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const (
	windowsHandoffTestEnv      = "WIRE_CONNECT_UPDATE_HANDOFF_TEST"
	windowsAdminFixtureTestEnv = "WIRE_CONNECT_UPDATE_ADMIN_TEST"
)

// TestMain gives the handoff test a real executable that understands the
// hidden updater commands.  The generated Go test binary is a valid Windows
// PE image, and appending a marker creates a distinct image without changing
// its executable sections.
func TestMain(m *testing.M) {
	if os.Getenv(windowsHandoffTestEnv) == "1" {
		os.Exit(runWindowsHandoffTestProcess())
	}
	os.Exit(m.Run())
}

func runWindowsHandoffTestProcess() int {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case applyUpdateCommand:
			if err := Apply(context.Background(), os.Args[2:], os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			return 0
		case cleanupUpdateCommand:
			if err := Cleanup(context.Background(), os.Args[2:], os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			return 0
		case "__refresh-update":
			return 0
		}
	}
	return runWindowsHandoffParent()
}

func runWindowsHandoffParent() int {
	target := os.Getenv(windowsHandoffTestEnv + "_TARGET")
	source := os.Getenv(windowsHandoffTestEnv + "_SOURCE")
	if target == "" || source == "" {
		fmt.Fprintln(os.Stderr, "missing Windows handoff test paths")
		return 1
	}
	image, err := os.ReadFile(source)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	pending, err := installStagedExecutable(context.Background(), source, target, digestBytes(image), extractedPackage{
		Executable:    image,
		Wintun:        []byte("wintun test runtime"),
		WintunLicense: []byte("wintun test license"),
	}, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if !pending {
		fmt.Fprintln(os.Stderr, "Windows handoff did not become pending")
		return 1
	}
	return 0
}

func TestWindowsHandoffReplacesRunningImageAndCleansStaging(t *testing.T) {
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	current, err = filepath.Abs(current)
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	image = append(image, []byte("wire-connect Windows handoff test image")...)

	dir := windowsHandoffTestDirectory(t)
	target := filepath.Join(dir, "wire-connect-handoff-target.exe")
	if err := os.WriteFile(target, mustReadFile(t, current), 0755); err != nil {
		t.Fatal(err)
	}
	// An elevated test process cannot safely update an executable below a
	// user-controlled temporary directory. Give the private fixture the same
	// owner and protected DACL expected from a machine installation, then run
	// the normal handoff through its production path checks. A linked/restricted
	// token keeps the ordinary user-owned t.TempDir path and exercises the
	// per-user policy instead.
	if windows.GetCurrentProcessToken().IsElevated() {
		protectWindowsHandoffFile(t, target)
	}
	sourceFile, err := os.CreateTemp(dir, ".wire-connect-executable-*")
	if err != nil {
		t.Fatal(err)
	}
	source := sourceFile.Name()
	if err := sourceFile.Chmod(0755); err != nil {
		sourceFile.Close()
		t.Fatal(err)
	}
	if _, err := sourceFile.Write(image); err != nil {
		sourceFile.Close()
		t.Fatal(err)
	}
	if err := sourceFile.Sync(); err != nil {
		sourceFile.Close()
		t.Fatal(err)
	}
	if err := sourceFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Run the parent from the exact image that the updater is replacing.  This
	// keeps the executable open through the handoff and exercises Windows'
	// sharing rules instead of merely testing a rename of an idle copy.
	cmd := exec.Command(target, "-test.run=TestWindowsHandoffParent")
	cmd.Env = append(os.Environ(), windowsHandoffTestEnv+"=1", windowsHandoffTestEnv+"_TARGET="+target, windowsHandoffTestEnv+"_SOURCE="+source)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("handoff parent failed: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		got, readErr := os.ReadFile(target)
		if readErr == nil && string(got) == string(image) && windowsHandoffArtifactsGone(dir, source) {
			break
		}
		if time.Now().After(deadline) {
			if readErr != nil {
				t.Fatalf("updated target was not produced: %v", readErr)
			}
			t.Fatalf("updated target has %d bytes; want %d", len(got), len(image))
		}
		time.Sleep(100 * time.Millisecond)
	}

	for name, want := range map[string]string{
		"wintun.dll":         "wintun test runtime",
		"WINTUN-LICENSE.txt": "wintun test license",
	} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read installed %s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("installed %s = %q; want %q", name, got, want)
		}
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("staged executable still exists, stat error = %v", err)
	}
	for _, pattern := range []string{
		".wire-connect-runtime-*",
		".wire-connect-update-helper-*",
		".wire-connect-update-transaction-*",
		".wire-connect-old-*",
	} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("handoff left %s files: %s", pattern, strings.Join(matches, ", "))
		}
	}
}

// TestWindowsInterruptedHandoffResumesFromInstalledTarget models a helper
// exiting after it renamed the executable source, but before it installed the
// runtime sidecars. The transaction is deliberately left with a missing
// executable source, an already-installed target, and its old backup. A fresh
// helper must accept that state, finish the remaining files, and clean the
// transaction through the same hidden entry points used in production.
func TestWindowsInterruptedHandoffResumesFromInstalledTarget(t *testing.T) {
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	current, err = filepath.Abs(current)
	if err != nil {
		t.Fatal(err)
	}
	oldImage, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	newImage := append(append([]byte(nil), oldImage...), []byte("wire-connect interrupted handoff image")...)

	dir := windowsHandoffTestDirectory(t)
	target := filepath.Join(dir, "wire-connect-recovery-target.exe")
	if err := os.WriteFile(target, newImage, 0755); err != nil {
		t.Fatal(err)
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		protectWindowsHandoffFile(t, target)
	}

	// The executable source has already been renamed into target. Leave its
	// authenticated old backup in place so the transaction can distinguish a
	// completed executable from a missing or untrusted installation.
	executableSource := filepath.Join(dir, ".wire-connect-executable-recovery")
	executableBackup := filepath.Join(dir, ".wire-connect-old-executable-recovery")
	if err := os.WriteFile(executableBackup, oldImage, 0600); err != nil {
		t.Fatal(err)
	}

	helpImage, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, ".wire-connect-update-helper-recovery.exe")
	if err := os.WriteFile(helper, helpImage, 0755); err != nil {
		t.Fatal(err)
	}

	type runtimeFixture struct {
		name       string
		old, fresh []byte
		source     string
		backup     string
	}
	runtimes := []runtimeFixture{
		{
			name:   "wintun.dll",
			old:    []byte("old Wintun runtime"),
			fresh:  []byte("new Wintun runtime"),
			source: filepath.Join(dir, ".wire-connect-runtime-wintun"),
			backup: filepath.Join(dir, ".wire-connect-old-wintun"),
		},
		{
			name:   "WINTUN-LICENSE.txt",
			old:    []byte("old Wintun license"),
			fresh:  []byte("new Wintun license"),
			source: filepath.Join(dir, ".wire-connect-runtime-license"),
			backup: filepath.Join(dir, ".wire-connect-old-license"),
		},
	}
	for _, item := range runtimes {
		if err := os.WriteFile(filepath.Join(dir, item.name), item.old, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(item.source, item.fresh, 0600); err != nil {
			t.Fatal(err)
		}
	}

	tx := windowsUpdateTransaction{
		Version: windowsUpdateTransactionVersion,
		// No process with this PID can exist, so recovery does not wait for an
		// unrelated process. A real interrupted transaction contains the
		// original PID and creation time, which waitForWindowsParent validates.
		ParentPID:    ^uint32(0),
		ParentStart:  1,
		Source:       executableSource,
		Target:       target,
		SHA256:       digestBytes(newImage),
		TargetBackup: executableBackup,
		Helper:       helper,
		HelperSHA256: digestBytes(helpImage),
	}
	for _, item := range runtimes {
		tx.Runtime = append(tx.Runtime, windowsRuntimeUpdate{
			Source: item.source,
			Target: filepath.Join(dir, item.name),
			SHA256: digestBytes(item.fresh),
			Backup: item.backup,
		})
	}
	txPath, err := writeWindowsTransaction(context.Background(), dir, tx)
	if err != nil {
		t.Fatal(err)
	}

	// Run the helper in a separate process. This allows its cleanup child to
	// wait for the helper to exit exactly as it does after a real handoff.
	cmd := exec.Command(current, applyUpdateCommand, "--transaction", txPath)
	cmd.Env = append(os.Environ(), windowsHandoffTestEnv+"=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("recovery helper failed: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		got, readErr := os.ReadFile(target)
		if readErr == nil && string(got) == string(newImage) && windowsHandoffArtifactsGone(dir, executableSource) {
			break
		}
		if time.Now().After(deadline) {
			if readErr != nil {
				t.Fatalf("recovered target was not produced: %v", readErr)
			}
			t.Fatalf("recovered target has %d bytes; want %d", len(got), len(newImage))
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, item := range runtimes {
		got, err := os.ReadFile(filepath.Join(dir, item.name))
		if err != nil {
			t.Fatalf("read recovered %s: %v", item.name, err)
		}
		if string(got) != string(item.fresh) {
			t.Fatalf("recovered %s = %q; want %q", item.name, got, item.fresh)
		}
	}
}

func windowsHandoffArtifactsGone(dir, source string) bool {
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		return false
	}
	for _, pattern := range []string{
		".wire-connect-runtime-*",
		".wire-connect-update-helper-*",
		".wire-connect-update-transaction-*",
		".wire-connect-old-*",
	} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil || len(matches) != 0 {
			return false
		}
	}
	return true
}

func mustReadFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// windowsHandoffTestDirectory returns a private installation fixture whose
// ancestor chain is suitable for the elevated security policy. ProgramData is
// a machine-owned location on supported Windows systems; using it avoids the
// user-writable TEMP chain that an elevated `go test` process would otherwise
// (correctly) reject. Non-elevated tests retain t.TempDir so the ordinary
// current-user ownership path is covered as well.
func windowsHandoffTestDirectory(t *testing.T) string {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		return t.TempDir()
	}
	if os.Getenv(windowsAdminFixtureTestEnv) != "1" {
		t.Skipf("elevated Windows handoff fixture writes under ProgramData; set %s=1 for the administrator test", windowsAdminFixtureTestEnv)
	}
	base := os.Getenv("ProgramData")
	if base == "" {
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = `C:`
		}
		base = filepath.Join(drive+string(filepath.Separator), "ProgramData")
	}
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		t.Fatalf("machine-owned ProgramData is unavailable: %s (%v)", base, err)
	}
	dir, err := os.MkdirTemp(base, "wire-connect-update-test-")
	if err != nil {
		t.Fatalf("create elevated update fixture: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	protectWindowsHandoffDirectory(t, dir)
	return dir
}

func protectWindowsHandoffDirectory(t *testing.T, name string) {
	t.Helper()
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("create Administrators SID: %v", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatalf("create fixture directory security descriptor: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("read fixture directory DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, dacl, nil); err != nil {
		t.Fatalf("protect fixture directory %s: %v", name, err)
	}
}

func protectWindowsHandoffFile(t *testing.T, name string) {
	t.Helper()
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("create Administrators SID: %v", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatalf("create fixture file security descriptor: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("read fixture file DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, dacl, nil); err != nil {
		t.Fatalf("protect fixture file %s: %v", name, err)
	}
}
