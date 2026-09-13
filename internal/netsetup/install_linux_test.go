//go:build linux && (amd64 || arm64)

package netsetup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLinuxUnitUsesFixedHelperCommandAndSystemPath(t *testing.T) {
	identity := "1001"
	name := HelperName(identity)
	unit := string(linuxUnit(normalizedConfig{Executable: "/tmp/wirectl-connect", Identity: identity}, name))
	for _, want := range []string{
		`ExecStart="/usr/local/libexec/wire-connect/` + name + `/wirectl-connect" "__network-helper" "--identity" "1001" "--name" "` + name + `"`,
		"User=root",
		"Group=root",
		"Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"Environment=HOME=/",
		"CapabilityBoundingSet=CAP_NET_ADMIN",
		"AmbientCapabilities=CAP_NET_ADMIN",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("systemd unit lacks %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "/bin/sh") {
		t.Fatal("systemd unit unexpectedly invokes a shell")
	}
}

func TestLinuxStatusReportsMissingRecordAsNotInstalled(t *testing.T) {
	oldDir, oldSystemctl, oldOwner := linuxSystemdDirPath, linuxSystemctlPath, unixOwnerCheck
	t.Cleanup(func() { linuxSystemdDirPath, linuxSystemctlPath, unixOwnerCheck = oldDir, oldSystemctl, oldOwner })
	linuxSystemdDirPath = filepath.Join(repoNetsetupTestRoot(t), "systemd")
	if err := os.MkdirAll(linuxSystemdDirPath, 0700); err != nil {
		t.Fatal(err)
	}
	unixOwnerCheck = func(os.FileInfo, string) error { return nil }
	called := false
	linuxSystemctlPath = func() (string, error) {
		called = true
		return "", errors.New("systemctl must not be called")
	}
	_, err := statusPlatform(context.Background(), "1001")
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("status error = %v, want ErrNotInstalled", err)
	}
	if called {
		t.Fatal("status queried systemctl for a missing helper record")
	}
}

func TestLinuxInstallEnablesLingerAfterStartingHelper(t *testing.T) {
	root := repoNetsetupTestRoot(t)
	oldRoot, oldDir, oldSystemctl, oldLoginctl, oldCommands, oldOwner := unixInstallRoot, linuxSystemdDirPath, linuxSystemctlPath, linuxLoginctlPath, unixCommands, unixOwnerCheck
	t.Cleanup(func() {
		unixInstallRoot, linuxSystemdDirPath, linuxSystemctlPath, linuxLoginctlPath, unixCommands, unixOwnerCheck = oldRoot, oldDir, oldSystemctl, oldLoginctl, oldCommands, oldOwner
	})
	unixInstallRoot = filepath.Join(root, "libexec", "wire-connect")
	linuxSystemdDirPath = filepath.Join(root, "systemd")
	if err := os.MkdirAll(linuxSystemdDirPath, 0700); err != nil {
		t.Fatal(err)
	}
	unixOwnerCheck = func(os.FileInfo, string) error { return nil }
	commands := &netsetupCommandRecorder{}
	unixCommands = commands
	linuxSystemctlPath = func() (string, error) { return "/test/systemctl", nil }
	linuxLoginctlPath = func() (string, error) { return "/test/loginctl", nil }
	source := filepath.Join(root, "wirectl-connect")
	if err := os.WriteFile(source, []byte("helper"), 0755); err != nil {
		t.Fatal(err)
	}
	identity := testIdentity()
	name := HelperName(identity)
	if err := installPlatform(context.Background(), normalizedConfig{Executable: source, Identity: identity}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"/test/systemctl", "daemon-reload"},
		{"/test/systemctl", "enable", helperUnitName(name) + ".service"},
		{"/test/systemctl", "restart", helperUnitName(name) + ".service"},
		{"/test/loginctl", "enable-linger", identity},
	}
	if !reflect.DeepEqual(commands.calls, want) {
		t.Fatalf("system commands = %#v, want %#v", commands.calls, want)
	}
}
