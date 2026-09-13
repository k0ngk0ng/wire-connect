//go:build darwin && arm64

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

func TestDarwinPlistUsesRootHelperAndSeparateArguments(t *testing.T) {
	identity := "1001"
	name := HelperName(identity)
	plist := string(darwinPlist(normalizedConfig{Executable: "/tmp/wirectl-connect", Identity: identity}, name))
	for _, want := range []string{
		"<key>Label</key>",
		"com.k0ngk0ng.wire-connect." + name,
		"<key>UserName</key>",
		"<string>root</string>",
		"<key>PATH</key>",
		"/usr/sbin:/usr/bin:/sbin:/bin",
		"<string>__network-helper</string>",
		"<string>--identity</string>",
		"<string>1001</string>",
		"<string>--name</string>",
		"<string>" + name + "</string>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("LaunchDaemon plist lacks %q:\n%s", want, plist)
		}
	}
	if strings.Contains(plist, "/bin/sh") {
		t.Fatal("LaunchDaemon plist unexpectedly invokes a shell")
	}
}

func TestDarwinStatusReportsMissingRecordAsNotInstalled(t *testing.T) {
	oldDir, oldLaunchctl, oldOwner := darwinLaunchdDirPath, darwinLaunchctlPath, unixOwnerCheck
	t.Cleanup(func() { darwinLaunchdDirPath, darwinLaunchctlPath, unixOwnerCheck = oldDir, oldLaunchctl, oldOwner })
	darwinLaunchdDirPath = filepath.Join(repoNetsetupTestRoot(t), "LaunchDaemons")
	if err := os.MkdirAll(darwinLaunchdDirPath, 0700); err != nil {
		t.Fatal(err)
	}
	unixOwnerCheck = func(os.FileInfo, string) error { return nil }
	called := false
	darwinLaunchctlPath = func() (string, error) {
		called = true
		return "", errors.New("launchctl must not be called")
	}
	_, err := statusPlatform(context.Background(), "1001")
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("status error = %v, want ErrNotInstalled", err)
	}
	if called {
		t.Fatal("status queried launchctl for a missing helper record")
	}
}

func TestDarwinInstallEnablesBeforeBootstrappingReplacement(t *testing.T) {
	root := repoNetsetupTestRoot(t)
	oldRoot, oldDir, oldLaunchctl, oldCommands, oldOwner := unixInstallRoot, darwinLaunchdDirPath, darwinLaunchctlPath, unixCommands, unixOwnerCheck
	t.Cleanup(func() {
		unixInstallRoot, darwinLaunchdDirPath, darwinLaunchctlPath, unixCommands, unixOwnerCheck = oldRoot, oldDir, oldLaunchctl, oldCommands, oldOwner
	})
	unixInstallRoot = filepath.Join(root, "libexec", "wire-connect")
	darwinLaunchdDirPath = filepath.Join(root, "LaunchDaemons")
	if err := os.MkdirAll(darwinLaunchdDirPath, 0700); err != nil {
		t.Fatal(err)
	}
	unixOwnerCheck = func(os.FileInfo, string) error { return nil }
	commands := &netsetupCommandRecorder{}
	unixCommands = commands
	darwinLaunchctlPath = func() (string, error) { return "/test/launchctl", nil }
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
		{"/test/launchctl", "enable", darwinHelperTarget(name)},
		{"/test/launchctl", "bootstrap", "system", darwinHelperPlistPath(name)},
		{"/test/launchctl", "kickstart", "-k", darwinHelperTarget(name)},
	}
	if !reflect.DeepEqual(commands.calls, want) {
		t.Fatalf("launchctl calls = %#v, want %#v", commands.calls, want)
	}
}
