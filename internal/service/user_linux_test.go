//go:build linux && (amd64 || arm64)

package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxUserInstallWritesForegroundUnitAndRestarts(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, "source-connect")
	if err := os.WriteFile(source, []byte("client image"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	oldHome, oldCommands, oldSystemctl := userHomeDir, userPlatformCommands, linuxUserSystemctl
	t.Cleanup(func() {
		userHomeDir, userPlatformCommands, linuxUserSystemctl = oldHome, oldCommands, oldSystemctl
	})
	userHomeDir = func() (string, error) { return home, nil }
	commands := &userRecordingCommands{}
	userPlatformCommands = commands
	linuxUserSystemctl = func() (string, error) { return "/test/systemctl", nil }

	state := filepath.Join(home, "state")
	if err := UserInstall(context.Background(), Config{Executable: source, StateDir: state, Name: "office"}); err != nil {
		t.Fatal(err)
	}
	installed, err := linuxUserInstalledExecutable("office")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(installed)
	if err != nil || string(got) != "client image" {
		t.Fatalf("installed executable = %q, %v", got, err)
	}
	st, err := os.Stat(installed)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0700 {
		t.Fatalf("installed executable mode = %04o; want 0700", st.Mode().Perm())
	}
	unitPath, err := linuxUserUnitPath("office")
	if err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	unitText := string(unit)
	for _, want := range []string{
		`resume" "--name" "office" "--state-dir" "` + state + `" "--foreground"`,
		"Restart=on-failure",
		"WantedBy=default.target",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(unitText, want) {
			t.Fatalf("user unit lacks %q:\n%s", want, unitText)
		}
	}
	if len(commands.calls) != 3 {
		t.Fatalf("systemctl calls = %#v; want reload, enable, restart", commands.calls)
	}
	for i, want := range [][]string{
		{"--user", "daemon-reload"},
		{"--user", "enable", "wire-connect-office.service"},
		{"--user", "restart", "wire-connect-office.service"},
	} {
		if got := commands.calls[i].args; len(got) != len(want) {
			t.Fatalf("systemctl call %d = %#v; want %#v", i, got, want)
		} else {
			for j := range want {
				if got[j] != want[j] {
					t.Fatalf("systemctl call %d = %#v; want %#v", i, got, want)
				}
			}
		}
	}
}

func TestLinuxUserStopDisablesAutomaticRestart(t *testing.T) {
	home := t.TempDir()
	oldHome, oldCommands, oldSystemctl, oldExists := userHomeDir, userPlatformCommands, linuxUserSystemctl, linuxUserUnitExists
	t.Cleanup(func() {
		userHomeDir, userPlatformCommands, linuxUserSystemctl, linuxUserUnitExists = oldHome, oldCommands, oldSystemctl, oldExists
	})
	userHomeDir = func() (string, error) { return home, nil }
	commands := &userRecordingCommands{}
	userPlatformCommands = commands
	linuxUserSystemctl = func() (string, error) { return "/test/systemctl", nil }
	linuxUserUnitExists = func(string) (bool, error) { return true, nil }

	if err := UserStop(context.Background(), "office"); err != nil {
		t.Fatal(err)
	}
	if len(commands.calls) != 1 || len(commands.calls[0].args) != 4 {
		t.Fatalf("systemctl calls = %#v; want one disable --now call", commands.calls)
	}
	want := []string{"--user", "disable", "--now", "wire-connect-office.service"}
	for i, value := range want {
		if commands.calls[0].args[i] != value {
			t.Fatalf("systemctl args = %#v; want %#v", commands.calls[0].args, want)
		}
	}
}

func TestLinuxUserStatusUsesNativeActiveState(t *testing.T) {
	home := t.TempDir()
	oldHome, oldCommands, oldSystemctl, oldExists := userHomeDir, userPlatformCommands, linuxUserSystemctl, linuxUserUnitExists
	t.Cleanup(func() {
		userHomeDir, userPlatformCommands, linuxUserSystemctl, linuxUserUnitExists = oldHome, oldCommands, oldSystemctl, oldExists
	})
	userHomeDir = func() (string, error) { return home, nil }
	commands := &userRecordingCommands{outputs: map[string][]byte{
		"--user\x00is-active\x00wire-connect-office.service": []byte("active\n"),
	}}
	userPlatformCommands = commands
	linuxUserSystemctl = func() (string, error) { return "/test/systemctl", nil }
	linuxUserUnitExists = func(string) (bool, error) { return true, nil }

	got, err := UserStatus(context.Background(), "office")
	if err != nil || got != "active" {
		t.Fatalf("UserStatus = %q, %v; want active, nil", got, err)
	}
}

func TestLinuxUserCheckUsesCurrentUserManager(t *testing.T) {
	oldCommands, oldSystemctl := userPlatformCommands, linuxUserSystemctl
	t.Cleanup(func() { userPlatformCommands, linuxUserSystemctl = oldCommands, oldSystemctl })
	commands := &userRecordingCommands{}
	userPlatformCommands = commands
	linuxUserSystemctl = func() (string, error) { return "/test/systemctl", nil }
	if err := UserCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(commands.calls) != 1 || len(commands.calls[0].args) != 2 || commands.calls[0].args[0] != "--user" || commands.calls[0].args[1] != "show-environment" {
		t.Fatalf("systemctl check = %#v; want --user show-environment", commands.calls)
	}
}
