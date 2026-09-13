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
}
