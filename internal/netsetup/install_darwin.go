//go:build darwin && arm64

package netsetup

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const launchdInstallDir = "/Library/LaunchDaemons"

var (
	darwinLaunchctlPath  = findDarwinLaunchctl
	darwinLaunchdDirPath = launchdInstallDir
)

func darwinNativeHelperName(name string) string {
	return "com.k0ngk0ng.wire-connect." + name
}

func darwinHelperTarget(name string) string {
	return "system/" + darwinNativeHelperName(name)
}

func darwinHelperPlistPath(name string) string {
	return filepath.Join(darwinLaunchdDirPath, darwinNativeHelperName(name)+".plist")
}

func installPlatform(ctx context.Context, cfg normalizedConfig) error {
	manager, err := darwinLaunchctlPath()
	if err != nil {
		return err
	}
	name := HelperName(cfg.Identity)
	if name == "" {
		return errors.New("wire-connect: could not derive helper name")
	}
	if err := copyUnixProtected(ctx, cfg.Executable, helperExecutable(name)); err != nil {
		return fmt.Errorf("wire-connect: install network helper executable: %w", err)
	}
	plist := darwinHelperPlistPath(name)
	if err := writeUnixRecordProtected(ctx, plist, darwinPlist(cfg, name), 0644); err != nil {
		return fmt.Errorf("wire-connect: install network helper LaunchDaemon: %w", err)
	}
	target := darwinHelperTarget(name)
	// Clear launchd's persistent disabled override before bootstrapping a
	// replacement. On a first install the label is not loaded yet, so enable's
	// expected "not loaded" result is deferred until after bootstrap.
	enabledBeforeBootstrap := false
	if err := runUnixCommand(ctx, manager, "enable", target); err == nil {
		enabledBeforeBootstrap = true
	} else if !isLaunchdNotLoaded(err) {
		return fmt.Errorf("wire-connect: enable network helper LaunchDaemon: %w", err)
	}
	if err := runUnixCommand(ctx, manager, "bootstrap", "system", plist); err != nil {
		// A previous installation can still be bootstrapped even when launchctl
		// rejected the new plist. Unload only after bootstrap reports failure,
		// then retry with the protected plist.
		if unloadErr := runUnixCommand(ctx, manager, "bootout", target); unloadErr != nil && !isLaunchdNotLoaded(unloadErr) {
			return fmt.Errorf("wire-connect: bootstrap network helper LaunchDaemon: %w (also failed to replace existing job: %v)", err, unloadErr)
		}
		if retryErr := runUnixCommand(ctx, manager, "bootstrap", "system", plist); retryErr != nil {
			return fmt.Errorf("wire-connect: bootstrap network helper LaunchDaemon after replacement: %w", retryErr)
		}
	}
	if !enabledBeforeBootstrap {
		if err := runUnixCommand(ctx, manager, "enable", target); err != nil {
			return fmt.Errorf("wire-connect: enable network helper LaunchDaemon: %w", err)
		}
	}
	if err := runUnixCommand(ctx, manager, "kickstart", "-k", target); err != nil {
		return fmt.Errorf("wire-connect: start network helper LaunchDaemon: %w", err)
	}
	return nil
}

func stopPlatform(ctx context.Context, identity string) error {
	manager, err := darwinLaunchctlPath()
	if err != nil {
		return err
	}
	name := HelperName(identity)
	if name == "" {
		return errors.New("wire-connect: could not derive helper name")
	}
	plist := darwinHelperPlistPath(name)
	plistExists, err := darwinRecordExists(plist)
	if err != nil {
		return err
	}
	if !plistExists {
		return fmt.Errorf("%w: %q", ErrNotInstalled, identity)
	}
	target := darwinHelperTarget(name)
	if err := runUnixCommand(ctx, manager, "disable", target); err != nil && !isLaunchdNotLoaded(err) {
		return fmt.Errorf("wire-connect: disable network helper: %w", err)
	}
	if err := runUnixCommand(ctx, manager, "bootout", target); err != nil && !isLaunchdNotLoaded(err) {
		return fmt.Errorf("wire-connect: stop network helper: %w", err)
	}
	return nil
}

func uninstallPlatform(ctx context.Context, identity string) error {
	manager, err := darwinLaunchctlPath()
	if err != nil {
		return err
	}
	name := HelperName(identity)
	if name == "" {
		return errors.New("wire-connect: could not derive helper name")
	}
	plist := darwinHelperPlistPath(name)
	dir := helperDir(name)
	plistExists, err := darwinRecordExists(plist)
	if err != nil {
		return err
	}
	dirExists, err := darwinDirExists(dir)
	if err != nil {
		return err
	}
	if !plistExists && !dirExists {
		return nil
	}
	target := darwinHelperTarget(name)
	if plistExists {
		if err := runUnixCommand(ctx, manager, "disable", target); err != nil && !isLaunchdNotLoaded(err) {
			return fmt.Errorf("wire-connect: disable network helper before uninstall: %w", err)
		}
		if err := runUnixCommand(ctx, manager, "bootout", target); err != nil && !isLaunchdNotLoaded(err) {
			return fmt.Errorf("wire-connect: stop network helper before uninstall: %w", err)
		}
		if err := runUnixCommand(ctx, manager, "enable", target); err != nil && !isLaunchdNotLoaded(err) {
			return fmt.Errorf("wire-connect: clear network helper disabled state: %w", err)
		}
		if err := removeUnixRecord(plist, darwinLaunchdDirPath); err != nil {
			return fmt.Errorf("wire-connect: remove network helper LaunchDaemon: %w", err)
		}
	}
	if dirExists {
		if err := removeUnixInstalledDir(dir); err != nil {
			return fmt.Errorf("wire-connect: remove network helper executable: %w", err)
		}
	}
	return nil
}

func statusPlatform(ctx context.Context, identity string) (string, error) {
	name := HelperName(identity)
	if name == "" {
		return "", errors.New("wire-connect: could not derive helper name")
	}
	plistExists, err := darwinRecordExists(darwinHelperPlistPath(name))
	if err != nil {
		return "", err
	}
	if !plistExists {
		return "", fmt.Errorf("%w: %q", ErrNotInstalled, identity)
	}
	manager, err := darwinLaunchctlPath()
	if err != nil {
		return "", err
	}
	out, err := outputUnixCommand(ctx, manager, "print", darwinHelperTarget(name))
	if err != nil {
		return "", fmt.Errorf("wire-connect: query network helper: %w", err)
	}
	if state := launchdState(out); state != "" {
		return state, nil
	}
	return "loaded", nil
}

func findDarwinLaunchctl() (string, error) {
	for _, path := range []string{"/bin/launchctl", "/usr/bin/launchctl"} {
		st, err := os.Lstat(path)
		if err == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", errors.New("wire-connect: launchctl was not found at /bin/launchctl or /usr/bin/launchctl")
}

func darwinRecordExists(path string) (bool, error) {
	if err := checkUnixAncestors(filepath.Dir(filepath.Clean(path))); err != nil {
		return false, err
	}
	st, err := os.Lstat(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return false, fmt.Errorf("wire-connect: helper LaunchDaemon record %q is not a regular file", path)
	}
	return true, nil
}

func darwinDirExists(path string) (bool, error) {
	if err := checkUnixAncestors(filepath.Dir(filepath.Clean(path))); err != nil {
		return false, err
	}
	st, err := os.Lstat(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return false, fmt.Errorf("wire-connect: installed helper directory %q is not a real directory", path)
	}
	return true, nil
}

func darwinPlist(cfg normalizedConfig, name string) []byte {
	args := []string{helperExecutable(name), "__network-helper", "--identity", cfg.Identity, "--name", name}
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	plistString(&b, "Label", darwinNativeHelperName(name))
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, arg := range args {
		b.WriteString("\t\t<string>")
		_ = xml.EscapeText(&b, []byte(arg))
		b.WriteString("</string>\n")
	}
	b.WriteString("\t</array>\n")
	plistString(&b, "UserName", "root")
	plistString(&b, "GroupName", "wheel")
	b.WriteString("\t<key>EnvironmentVariables</key>\n\t<dict>\n")
	plistString(&b, "PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	plistString(&b, "HOME", "/")
	b.WriteString("\t</dict>\n")
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	b.WriteString("\t<key>KeepAlive</key>\n\t<true/>\n")
	b.WriteString("\t<key>ProcessType</key>\n\t<string>Background</string>\n")
	b.WriteString("\t<key>ThrottleInterval</key>\n\t<integer>5</integer>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes()
}

func plistString(b *bytes.Buffer, key, value string) {
	b.WriteString("\t<key>")
	_ = xml.EscapeText(b, []byte(key))
	b.WriteString("</key>\n\t<string>")
	_ = xml.EscapeText(b, []byte(value))
	b.WriteString("</string>\n")
}

func launchdState(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "state =") {
			return strings.TrimSpace(strings.TrimPrefix(line, "state ="))
		}
	}
	return ""
}

func isLaunchdNotLoaded(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, phrase := range []string{"could not find service", "no such process", "service is not loaded", "service not found", "domain does not support specified action", "no such file"} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}
