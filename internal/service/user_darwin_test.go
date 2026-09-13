//go:build darwin && (amd64 || arm64)

package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinUserInstallWritesLaunchAgentWithForegroundArgs(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, "source-connect")
	if err := os.WriteFile(source, []byte("client image"), 0755); err != nil {
		t.Fatal(err)
	}
	oldHome, oldCommands, oldLaunchctl, oldUID := userHomeDir, userPlatformCommands, darwinUserLaunchctl, darwinUserUID
	t.Cleanup(func() {
		userHomeDir, userPlatformCommands, darwinUserLaunchctl, darwinUserUID = oldHome, oldCommands, oldLaunchctl, oldUID
	})
	userHomeDir = func() (string, error) { return home, nil }
	commands := &userRecordingCommands{}
	userPlatformCommands = commands
	darwinUserLaunchctl = func() (string, error) { return "/test/launchctl", nil }
	darwinUserUID = func() int { return 501 }

	state := filepath.Join(home, "state")
	if err := UserInstall(context.Background(), Config{Executable: source, StateDir: state, Name: "office"}); err != nil {
		t.Fatal(err)
	}
	plistPath, err := darwinUserPlistPath("office")
	if err != nil {
		t.Fatal(err)
	}
	plist, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(plist)
	for _, want := range []string{
		"<key>Label</key>",
		"com.k0ngk0ng.wire-connect.office",
		"<string>resume</string>",
		"<string>--name</string>",
		"<string>office</string>",
		"<string>--state-dir</string>",
		"<string>" + state + "</string>",
		"<string>--foreground</string>",
		"<key>KeepAlive</key>",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("LaunchAgent plist lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "--service") {
		t.Fatalf("user LaunchAgent unexpectedly uses root service mode:\n%s", text)
	}
	if len(commands.calls) != 4 {
		t.Fatalf("launchctl calls = %#v; want bootout, bootstrap, enable, kickstart", commands.calls)
	}
	wantCalls := [][]string{
		{"bootout", "gui/501/com.k0ngk0ng.wire-connect.office"},
		{"enable", "gui/501/com.k0ngk0ng.wire-connect.office"},
		{"bootstrap", "gui/501", plistPath},
		{"kickstart", "-k", "gui/501/com.k0ngk0ng.wire-connect.office"},
	}
	for i, want := range wantCalls {
		if len(commands.calls[i].args) != len(want) {
			t.Fatalf("launchctl call %d = %#v; want %#v", i, commands.calls[i].args, want)
		}
		for j, value := range want {
			if commands.calls[i].args[j] != value {
				t.Fatalf("launchctl call %d = %#v; want %#v", i, commands.calls[i].args, want)
			}
		}
	}
}

func TestDarwinUserStopPersistsDisabledState(t *testing.T) {
	home := t.TempDir()
	oldHome, oldCommands, oldLaunchctl, oldUID := userHomeDir, userPlatformCommands, darwinUserLaunchctl, darwinUserUID
	t.Cleanup(func() {
		userHomeDir, userPlatformCommands, darwinUserLaunchctl, darwinUserUID = oldHome, oldCommands, oldLaunchctl, oldUID
	})
	userHomeDir = func() (string, error) { return home, nil }
	commands := &userRecordingCommands{}
	userPlatformCommands = commands
	darwinUserLaunchctl = func() (string, error) { return "/test/launchctl", nil }
	darwinUserUID = func() int { return 501 }
	plist, err := darwinUserPlistPath("office")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(plist), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte("plist"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := UserStop(context.Background(), "office"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"disable", "gui/501/com.k0ngk0ng.wire-connect.office"},
		{"bootout", "gui/501/com.k0ngk0ng.wire-connect.office"},
	}
	if len(commands.calls) != len(want) {
		t.Fatalf("launchctl calls = %#v; want %#v", commands.calls, want)
	}
	for i := range want {
		for j := range want[i] {
			if commands.calls[i].args[j] != want[i][j] {
				t.Fatalf("launchctl call %d = %#v; want %#v", i, commands.calls[i].args, want[i])
			}
		}
	}
}

func TestDarwinUserCheckUsesCurrentGUIUserDomain(t *testing.T) {
	oldCommands, oldLaunchctl, oldUID := userPlatformCommands, darwinUserLaunchctl, darwinUserUID
	t.Cleanup(func() { userPlatformCommands, darwinUserLaunchctl, darwinUserUID = oldCommands, oldLaunchctl, oldUID })
	commands := &userRecordingCommands{}
	userPlatformCommands = commands
	darwinUserLaunchctl = func() (string, error) { return "/test/launchctl", nil }
	darwinUserUID = func() int { return 501 }
	if err := UserCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(commands.calls) != 1 || len(commands.calls[0].args) != 2 || commands.calls[0].args[0] != "print" || commands.calls[0].args[1] != "gui/501" {
		t.Fatalf("launchctl check = %#v; want print gui/501", commands.calls)
	}
}
