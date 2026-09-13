//go:build (linux && (amd64 || arm64)) || (darwin && arm64) || (windows && amd64)

package netsetup

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type netsetupCommandRecorder struct {
	calls [][]string
}

func (r *netsetupCommandRecorder) Run(_ context.Context, name string, args ...string) error {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	return nil
}

func (r *netsetupCommandRecorder) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	return nil, nil
}

func TestCurrentIdentityAndHelperName(t *testing.T) {
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if identity == "" {
		t.Fatal("CurrentIdentity returned an empty identity")
	}
	if _, err := normalizeIdentity(identity); err != nil {
		t.Fatalf("current identity is not accepted: %v", err)
	}
	name := HelperName(identity)
	if !strings.HasPrefix(name, "helper-") || len(name) != len("helper-")+32 {
		t.Fatalf("HelperName(%q) = %q, want helper- plus 32 hex characters", identity, name)
	}
	if name != HelperName(identity) {
		t.Fatal("HelperName is not deterministic")
	}
	if HelperName("not-an-identity") != "" {
		t.Fatal("HelperName accepted an invalid identity")
	}
}

func TestEnsureRequestsElevationForCurrentIdentityOnly(t *testing.T) {
	root := repoNetsetupTestRoot(t)
	executable := filepath.Join(root, "wirectl-connect")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	oldIdentity, oldElevated, oldRequest := currentIdentityFn, elevatedFn, requestElevationFn
	t.Cleanup(func() { currentIdentityFn, elevatedFn, requestElevationFn = oldIdentity, oldElevated, oldRequest })
	currentIdentityFn = func() (string, error) { return identity, nil }
	elevatedFn = func() bool { return false }
	called := false
	requestElevationFn = func(ctx context.Context, gotExecutable, gotIdentity string, _ io.Reader, _, _ io.Writer) error {
		called = true
		if err := contextErr(ctx); err != nil {
			return err
		}
		if gotExecutable != executable || gotIdentity != identity {
			t.Fatalf("elevation request = (%q, %q)", gotExecutable, gotIdentity)
		}
		return nil
	}
	if err := Ensure(context.Background(), executable, "", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("Ensure did not request elevation")
	}
	called = false
	if err := Ensure(context.Background(), executable, differentTestIdentity(identity), nil, nil, nil); err == nil {
		t.Fatal("Ensure accepted another user's identity")
	}
	if called {
		t.Fatal("Ensure requested elevation for another user's identity")
	}
}

func TestEnsureElevatedInstallsWithoutElevationChild(t *testing.T) {
	root := repoNetsetupTestRoot(t)
	executable := filepath.Join(root, "wirectl-connect")
	if err := os.WriteFile(executable, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	oldIdentity, oldElevated, oldInstall := currentIdentityFn, elevatedFn, installPlatformFn
	t.Cleanup(func() { currentIdentityFn, elevatedFn, installPlatformFn = oldIdentity, oldElevated, oldInstall })
	identity, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	currentIdentityFn = func() (string, error) { return identity, nil }
	elevatedFn = func() bool { return true }
	called := false
	installPlatformFn = func(_ context.Context, cfg normalizedConfig) error {
		called = true
		if cfg.Identity != identity || cfg.Executable != executable {
			t.Fatalf("install config = %#v", cfg)
		}
		return nil
	}
	if err := Ensure(context.Background(), executable, "", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("Ensure did not install directly when elevated")
	}
}

func TestInstallRequiresElevationBeforePlatformCall(t *testing.T) {
	root := repoNetsetupTestRoot(t)
	executable := filepath.Join(root, "wirectl-connect")
	if err := os.WriteFile(executable, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	oldElevated := elevatedFn
	t.Cleanup(func() { elevatedFn = oldElevated })
	elevatedFn = func() bool { return false }
	err := Install(context.Background(), Config{Executable: executable, Identity: testIdentity()})
	if !errors.Is(err, ErrElevationRequired) {
		t.Fatalf("Install error = %v, want ErrElevationRequired", err)
	}
}

func testIdentity() string {
	identity, err := CurrentIdentity()
	if err != nil {
		return "0"
	}
	return identity
}

func differentTestIdentity(identity string) string {
	if runtime.GOOS == "windows" {
		if identity != "S-1-5-18" {
			return "S-1-5-18"
		}
		return "S-1-5-19"
	}
	if identity != "0" {
		return "0"
	}
	return "1"
}

func repoNetsetupTestRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(".cache", "netsetup-tests")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "case-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}
