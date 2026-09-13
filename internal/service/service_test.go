package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

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
