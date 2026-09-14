package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	serviceCommandHelperEnv  = "WIRE_CONNECT_SERVICE_COMMAND_HELPER"
	serviceCommandHelperMode = "WIRE_CONNECT_SERVICE_COMMAND_HELPER_MODE"
)

// TestServiceCommandHelper is launched by the command-runner cancellation
// tests. Keeping the helper in this test binary avoids relying on a platform
// shell or on a checked-in executable fixture.
func TestServiceCommandHelper(t *testing.T) {
	if os.Getenv(serviceCommandHelperEnv) != "1" {
		return
	}
	if os.Getenv(serviceCommandHelperMode) != "sleep" {
		t.Fatalf("unknown command helper mode %q", os.Getenv(serviceCommandHelperMode))
	}
	time.Sleep(10 * time.Second)
}

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
		bad   bool
	}{
		{input: "", want: "default"},
		{input: "office-1", want: "office-1"},
		{input: "a_b", want: "a_b"},
		{input: "bad.name", bad: true},
		{input: "-bad", bad: true},
		{input: "bad name", bad: true},
		{input: strings.Repeat("a", 65), bad: true},
	}
	for _, tt := range tests {
		got, err := normalizeName(tt.input)
		if tt.bad {
			if err == nil {
				t.Fatalf("normalizeName(%q) accepted invalid name", tt.input)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Fatalf("normalizeName(%q) = %q, %v; want %q", tt.input, got, err, tt.want)
		}
	}
}

func TestNormalizeConfigResolvesAbsolutePathsAndKeepsServiceArgsSeparate(t *testing.T) {
	got, err := normalizeConfig(Config{
		Executable: filepath.Join("bin", "wirectl-connect"),
		StateDir:   filepath.Join("profiles", "office one"),
		Name:       "office-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got.Executable) || !filepath.IsAbs(got.StateDir) {
		t.Fatalf("normalized paths are not absolute: %#v", got)
	}
	args := serviceArgs(got)
	want := []string{"resume", "--state-dir", got.StateDir, "--name", "office-1", "--service"}
	if len(args) != len(want) {
		t.Fatalf("service args = %#v; want %#v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("service args = %#v; want %#v", args, want)
		}
	}
}

func TestNormalizeConfigRejectsEmptyAndNULPaths(t *testing.T) {
	for _, cfg := range []Config{
		{StateDir: "/var/lib/wire-connect"},
		{Executable: "/usr/local/bin/wirectl-connect"},
		{Executable: "/tmp/with\x00nul", StateDir: "/var/lib/wire-connect"},
		{Executable: "/usr/local/bin/wirectl-connect", StateDir: "/tmp/with\x00nul"},
	} {
		if _, err := normalizeConfig(cfg); err == nil {
			t.Fatalf("normalizeConfig(%#v) unexpectedly succeeded", cfg)
		}
	}
}

func TestContextErr(t *testing.T) {
	if err := contextErr(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(contextErr(ctx), context.Canceled) {
		t.Fatalf("contextErr(%v) did not return context.Canceled", ctx.Err())
	}
	if err := contextErr(nil); err == nil {
		t.Fatal("contextErr(nil) succeeded")
	}
}

func TestExecCommandRunnerPreservesContextDeadline(t *testing.T) {
	t.Setenv(serviceCommandHelperEnv, "1")
	t.Setenv(serviceCommandHelperMode, "sleep")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := (execCommandRunner{}).Output(ctx, os.Args[0], "-test.run=^TestServiceCommandHelper$")
	if err == nil {
		t.Fatal("command unexpectedly succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("command error = %v; want context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("command error = %v; want a readable deadline cause", err)
	}
}

func TestExecCommandRunnerPreservesContextCancellation(t *testing.T) {
	t.Setenv(serviceCommandHelperEnv, "1")
	t.Setenv(serviceCommandHelperMode, "sleep")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := (execCommandRunner{}).Output(ctx, os.Args[0], "-test.run=^TestServiceCommandHelper$")
		result <- err
	}()
	t.Cleanup(cancel)

	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		cancel()
	case err := <-result:
		t.Fatalf("command returned before cancellation: %v", err)
	}

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("command unexpectedly succeeded")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("command error = %v; want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("command did not stop after context cancellation")
	}
}
