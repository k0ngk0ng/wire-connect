package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "state")}
	p := Profile{Server: "https://example.com", Secret: []byte("secret"), PairID: "pair"}
	if err := s.Write("default", p); err != nil {
		t.Fatal(err)
	}
	var got Profile
	if err := s.Read("default", &got); err != nil {
		t.Fatal(err)
	}
	if got.Server != p.Server || string(got.Secret) != string(p.Secret) {
		t.Fatal("state did not round trip")
	}
	if err := s.Write("../escape", p); err == nil {
		t.Fatal("accepted path traversal")
	}
	if err := s.Write("default", Profile{PairID: "replacement"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Read("default", &got); err != nil || got.PairID != "replacement" {
		t.Fatal(got, err)
	}
}

func TestRefuseSymlinkAndPublicSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions and symlink policy; Windows uses a protected DACL")
	}
	d := t.TempDir()
	s := Store{Dir: filepath.Join(d, "state")}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(d, "target")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(s.Dir, "linked.json")); err != nil {
		t.Fatal(err)
	}
	if err := s.Write("linked", map[string]string{"x": "y"}); err == nil {
		t.Fatal("replaced symlink")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "preserve" {
		t.Fatal("modified target")
	}
	if err := os.WriteFile(filepath.Join(s.Dir, "unsafe.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	var got any
	if err := s.Read("unsafe", &got); err == nil {
		t.Fatal("read world-readable secrets")
	}
	before, err := os.ReadFile(filepath.Join(s.Dir, "unsafe.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write("unsafe", map[string]string{"changed": "no"}); err == nil {
		t.Fatal("wrote world-readable secret")
	}
	after, err := os.ReadFile(filepath.Join(s.Dir, "unsafe.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("modified public state file: before %q, after %q", before, after)
	}
}

func TestStoreInitRefusesExistingPublicDirectoryWithoutChangingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions; Windows uses a protected DACL")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := before.Mode().Perm(); got != 0755 {
		t.Fatalf("test directory mode is %04o, want 0755", got)
	}
	if err := (Store{Dir: dir}).Init(); err == nil {
		t.Fatal("accepted a non-private existing state directory")
	}
	after, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.Mode().Perm(); got != before.Mode().Perm() {
		t.Fatalf("changed existing directory mode from %04o to %04o", before.Mode().Perm(), got)
	}
}

func TestStoreInitRefusesFilesystemRootWithoutChangingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("filesystem root handling differs on Windows")
	}
	root := string(filepath.Separator)
	before, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := (Store{Dir: root}).Init(); err == nil {
		t.Fatal("accepted filesystem root as state directory")
	}
	after, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.Mode().Perm(); got != before.Mode().Perm() {
		t.Fatalf("changed filesystem root mode from %04o to %04o", before.Mode().Perm(), got)
	}
}

func TestStoreInitRefusesFinalDirectorySymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix symlink policy; Windows uses reparse-point checks")
	}
	d := t.TempDir()
	target := filepath.Join(d, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "state")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := (Store{Dir: link}).Init(); err == nil {
		t.Fatal("accepted a symlink as state directory")
	}
}

func TestStoreRefusesForeignOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership policy; Windows uses a protected DACL")
	}
	if os.Geteuid() != 0 {
		t.Skip("changing ownership requires root")
	}
	foreignUID := 1
	if foreignUID == os.Geteuid() {
		foreignUID = 2
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, foreignUID, -1); err != nil {
		t.Skipf("cannot create foreign-owned test directory: %v", err)
	}
	if err := (Store{Dir: dir}).Init(); err == nil {
		t.Fatal("accepted a private directory owned by another user")
	}
}
