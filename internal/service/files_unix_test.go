//go:build (linux && (amd64 || arm64)) || (darwin && (amd64 || arm64))

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureSecureInstallParentCreatesMissingTrustedDirectories(t *testing.T) {
	base := serviceFilesTestRoot(t)
	installRoot := filepath.Join(base, "libexec", "wire-connect")
	destination := filepath.Join(installRoot, "office")

	if err := ensureSecureInstallParentAt(destination, installRoot, testOwnerCheck); err != nil {
		t.Fatalf("ensureSecureInstallParentAt: %v", err)
	}
	for _, path := range []string{filepath.Dir(installRoot), installRoot, destination} {
		st, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat created directory %q: %v", path, err)
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			t.Fatalf("created path %q is not a real directory", path)
		}
		if got := st.Mode().Perm(); got != 0755 {
			t.Fatalf("created directory %q mode = %04o; want 0755", path, got)
		}
	}
}

func TestEnsureSecureInstallParentDoesNotRewriteExistingDirectory(t *testing.T) {
	base := serviceFilesTestRoot(t)
	parent := filepath.Join(base, "libexec")
	if err := os.Mkdir(parent, 0711); err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(parent, "wire-connect")
	if err := ensureSecureInstallParentAt(filepath.Join(installRoot, "office"), installRoot, testOwnerCheck); err != nil {
		t.Fatalf("ensureSecureInstallParentAt: %v", err)
	}
	st, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0711 {
		t.Fatalf("existing directory %q mode = %04o; want unchanged 0711", parent, got)
	}
}

func TestEnsureSecureInstallParentRejectsUnsafeExistingParent(t *testing.T) {
	tests := []struct {
		name string
		make func(string) error
		want string
	}{
		{
			name: "symlink",
			make: func(base string) error {
				target := filepath.Join(base, "target")
				if err := os.Mkdir(target, 0755); err != nil {
					return err
				}
				return os.Symlink(target, filepath.Join(base, "libexec"))
			},
			want: "real directory",
		},
		{
			name: "writable",
			make: func(base string) error {
				path := filepath.Join(base, "libexec")
				if err := os.Mkdir(path, 0755); err != nil {
					return err
				}
				return os.Chmod(path, 0777)
			},
			want: "writable by a non-root user",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := serviceFilesTestRoot(t)
			if err := tt.make(base); err != nil {
				t.Fatal(err)
			}
			installRoot := filepath.Join(base, "libexec", "wire-connect")
			err := ensureSecureInstallParentAt(filepath.Join(installRoot, "office"), installRoot, testOwnerCheck)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ensureSecureInstallParentAt error = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestEnsureSecureInstallParentRejectsWritableAncestor(t *testing.T) {
	base := serviceFilesTestRoot(t)
	ancestor := filepath.Join(base, "writable")
	existing := filepath.Join(ancestor, "local")
	if err := os.MkdirAll(existing, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ancestor, 0777); err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(existing, "libexec", "wire-connect")
	err := ensureSecureInstallParentAt(filepath.Join(installRoot, "office"), installRoot, testOwnerCheck)
	if err == nil || !strings.Contains(err.Error(), "writable by a non-root user") {
		t.Fatalf("unsafe ancestor accepted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(existing, "libexec")); !os.IsNotExist(err) {
		t.Fatalf("created directories before validating ancestors: %v", err)
	}
}

func serviceFilesTestRoot(t *testing.T) string {
	t.Helper()
	repo := serviceTestRepoRoot(t)
	base := filepath.Join(repo, ".cache", "service-files")
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "case-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func serviceTestRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if st, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && st.Mode().IsRegular() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository go.mod")
		}
		dir = parent
	}
}

func testOwnerCheck(os.FileInfo, string) error { return nil }
