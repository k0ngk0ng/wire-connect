//go:build windows

package installpath

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveWindowsRegularFile(t *testing.T) {
	root := installPathTestRoot(t)
	want := filepath.Join(root, "wirectl-connect.exe")
	if err := os.WriteFile(want, []byte("test executable"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := Resolve(want)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", want, err)
	}
	assertResolvedWindowsFile(t, got, want)
}

func TestResolveWindowsScoopCurrentJunction(t *testing.T) {
	root := installPathTestRoot(t)
	versionDir := filepath.Join(root, "1.2.3")
	binDir := filepath.Join(versionDir, "bin")
	if err := os.MkdirAll(binDir, 0700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(binDir, "wirectl-connect.exe")
	if err := os.WriteFile(want, []byte("test executable"), 0600); err != nil {
		t.Fatal(err)
	}

	currentDir := filepath.Join(root, "current")
	createWindowsJunction(t, currentDir, versionDir)
	input := filepath.Join(currentDir, "bin", "wirectl-connect.exe")

	got, err := Resolve(input)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", input, err)
	}
	assertResolvedWindowsFile(t, got, want)
	if normalizeWindowsFinalPath(got) == normalizeWindowsFinalPath(input) {
		t.Fatalf("Resolve(%q) returned the junction path %q", input, got)
	}
}

func TestResolveWindowsRejectsMissingFile(t *testing.T) {
	root := installPathTestRoot(t)
	missing := filepath.Join(root, "current", "bin", "wirectl-connect.exe")
	if _, err := Resolve(missing); err == nil {
		t.Fatalf("Resolve(%q) succeeded for a missing file", missing)
	}
}

func assertResolvedWindowsFile(t *testing.T, got, want string) {
	t.Helper()
	if !filepath.IsAbs(got) {
		t.Fatalf("resolved path %q is not absolute", got)
	}
	wantInfo, err := os.Stat(want)
	if err != nil {
		t.Fatalf("stat original file %q: %v", want, err)
	}
	gotInfo, err := os.Stat(got)
	if err != nil {
		t.Fatalf("stat resolved path %q: %v", got, err)
	}
	if !os.SameFile(wantInfo, gotInfo) {
		t.Fatalf("resolved path %q does not identify original file %q", got, want)
	}
}

func createWindowsJunction(t *testing.T, link, target string) {
	t.Helper()
	cmd := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("create junction %q -> %q: %v\n%s", link, target, err, output)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
}

func installPathTestRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if info, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && info.Mode().IsRegular() {
			base := filepath.Join(dir, ".cache", "installpath-windows")
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

func normalizeWindowsFinalPath(path string) string {
	path = filepath.Clean(path)
	path = strings.TrimPrefix(path, `\\?\`)
	path = strings.TrimPrefix(path, `\??\`)
	return strings.ToLower(filepath.Clean(path))
}
