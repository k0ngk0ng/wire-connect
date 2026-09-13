//go:build (linux && (amd64 || arm64)) || (darwin && arm64)

package netsetup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixProtectedCopyUsesPackageRootAndRejectsSymlink(t *testing.T) {
	root := repoNetsetupTestRoot(t)
	oldRoot, oldOwner := unixInstallRoot, unixOwnerCheck
	t.Cleanup(func() { unixInstallRoot, unixOwnerCheck = oldRoot, oldOwner })
	unixInstallRoot = filepath.Join(root, "libexec", "wire-connect")
	unixOwnerCheck = func(os.FileInfo, string) error { return nil }

	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("helper-image"), 0755); err != nil {
		t.Fatal(err)
	}
	name := HelperName(testIdentity())
	destination := filepath.Join(unixInstallRoot, name, "wirectl-connect")
	if err := copyUnixProtected(t.Context(), source, destination); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "helper-image" {
		t.Fatalf("installed helper = %q", got)
	}
	if mode := mustUnixStat(t, destination).Mode().Perm(); mode != 0755 {
		t.Fatalf("installed helper mode = %04o; want 0755", mode)
	}

	link := filepath.Join(unixInstallRoot, "helper-"+strings.Repeat("a", 32))
	if err := os.Symlink(filepath.Dir(destination), link); err != nil {
		t.Fatal(err)
	}
	err = copyUnixProtected(t.Context(), source, filepath.Join(link, "wirectl-connect"))
	if err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("copy through symlink = %v; want protected path error", err)
	}
}

func mustUnixStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st
}
