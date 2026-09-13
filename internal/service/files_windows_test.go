//go:build windows && amd64

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestWindowsRenameWithRetryRetriesTransientRefusals(t *testing.T) {
	oldRename := windowsRename
	t.Cleanup(func() { windowsRename = oldRename })
	var calls int
	windowsRename = func(string, string) error {
		calls++
		switch calls {
		case 1:
			return windows.ERROR_ACCESS_DENIED
		case 2:
			return windows.ERROR_SHARING_VIOLATION
		default:
			return nil
		}
	}
	if err := windowsRenameWithRetry(context.Background(), "old", "new", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("rename attempts = %d; want 3", calls)
	}
}

func TestAlreadyStoppedWindowsCopyRetriesTransientRefusal(t *testing.T) {
	oldRename, oldACL := windowsRename, windowsSetProtectedACL
	t.Cleanup(func() { windowsRename, windowsSetProtectedACL = oldRename, oldACL })
	windowsSetProtectedACL = func(string, bool) error { return nil }
	var calls int
	windowsRename = func(oldPath, newPath string) error {
		calls++
		if calls == 1 {
			return windows.ERROR_ACCESS_DENIED
		}
		return windows.Rename(oldPath, newPath)
	}

	service := &fakeWindowsService{
		queries: []svc.Status{{State: svc.Stopped}},
		config:  mgr.Config{StartType: mgr.StartAutomatic},
	}
	if err := stopAndDisableWindows(context.Background(), service, "office"); err != nil {
		t.Fatalf("stop already-stopped service: %v", err)
	}
	root := windowsServiceFilesTestRoot(t)
	source := filepath.Join(root, "source.exe")
	destination := filepath.Join(root, "installed.exe")
	if err := os.WriteFile(source, []byte("new image"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old image"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := windowsCopyAtomic(context.Background(), source, destination); err != nil {
		t.Fatalf("copy after already-stopped service: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new image" {
		t.Fatalf("installed image = %q; want new image", got)
	}
	if calls != 2 {
		t.Fatalf("rename attempts = %d; want transient refusal followed by success", calls)
	}
}

func TestWindowsRenameWithRetryPermanentRefusalHonorsTimeout(t *testing.T) {
	oldRename := windowsRename
	t.Cleanup(func() { windowsRename = oldRename })
	var calls int
	windowsRename = func(string, string) error {
		calls++
		return windows.ERROR_ACCESS_DENIED
	}
	started := time.Now()
	err := windowsRenameWithRetry(context.Background(), "old", "new", 250*time.Millisecond)
	if err == nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("permanent refusal error = %v; want wrapped access denied", err)
	}
	if calls < 2 {
		t.Fatalf("rename attempts = %d; want retry before timeout", calls)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("permanent refusal took %s; want bounded timeout", elapsed)
	}
}

func windowsServiceFilesTestRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if st, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && st.Mode().IsRegular() {
			base := filepath.Join(dir, ".cache", "service-files-windows")
			if err := os.MkdirAll(base, 0700); err != nil {
				t.Fatal(err)
			}
			caseDir, err := os.MkdirTemp(base, "case-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(caseDir) })
			return caseDir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository go.mod")
		}
		dir = parent
	}
}
