//go:build darwin && (amd64 || arm64)

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	darwinUserLaunchctl = findLaunchctl
	darwinUserUID       = os.Getuid
)

func userInstall(ctx context.Context, cfg normalizedConfig) error { return darwinUserInstall(ctx, cfg) }
func userStop(ctx context.Context, name string) error             { return darwinUserStop(ctx, name) }
func userUninstall(ctx context.Context, name string) error        { return darwinUserUninstall(ctx, name) }
func userStatus(ctx context.Context, name string) (string, error) { return darwinUserStatus(ctx, name) }
func userCheck(ctx context.Context) error                         { return darwinUserCheck(ctx) }

func userInstallBase(home string) string {
	return filepath.Join(home, "Library", "Application Support")
}

func darwinUserLabel(name string) string {
	return "com.k0ngk0ng.wire-connect." + name
}

func darwinUserTarget(name string) string {
	return fmt.Sprintf("gui/%d/%s", darwinUserUID(), darwinUserLabel(name))
}

func darwinUserInstalledDir(name string) (string, error) {
	home, err := userHomeDir()
	if err != nil {
		return "", fmt.Errorf("wire-connect: determine current user home: %w", err)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return "", err
	}
	return filepath.Join(userInstallBase(filepath.Clean(home)), "wire-connect", name), nil
}

func darwinUserInstalledExecutable(name string) (string, error) {
	dir, err := darwinUserInstalledDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wirectl-connect"), nil
}

func darwinUserPlistPath(name string) (string, error) {
	home, err := userHomeDir()
	if err != nil {
		return "", fmt.Errorf("wire-connect: determine current user home: %w", err)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Clean(home), "Library", "LaunchAgents", darwinUserLabel(name)+".plist"), nil
}

func darwinUserInstall(ctx context.Context, cfg normalizedConfig) error {
	installed, err := darwinUserInstalledExecutable(cfg.Name)
	if err != nil {
		return err
	}
	plist, err := darwinUserPlistPath(cfg.Name)
	if err != nil {
		return err
	}
	manager, err := darwinUserLaunchctl()
	if err != nil {
		return err
	}
	if err := userCopyAtomic(ctx, cfg.Executable, installed); err != nil {
		return fmt.Errorf("wire-connect: install user executable: %w", err)
	}
	if err := userWriteAtomic(ctx, plist, darwinUserPlist(cfg, installed), 0600); err != nil {
		return fmt.Errorf("wire-connect: install user LaunchAgent plist: %w", err)
	}
	target := darwinUserTarget(cfg.Name)
	// bootout is idempotent for an un-loaded profile and ensures an upgrade
	// cannot leave a process using an old plist or executable image.
	if err := runCommand(ctx, userPlatformCommands, manager, "bootout", target); err != nil && !isLaunchctlNotLoaded(err) {
		return fmt.Errorf("wire-connect: replace user LaunchAgent %q: %w", cfg.Name, err)
	}
	// Clear a persistent disabled override before bootstrap. launchctl can
	// reject bootstrap for a disabled label; on a first install it may report
	// that the label is not loaded, in which case enable it after bootstrap.
	enabledBeforeBootstrap := false
	if err := runCommand(ctx, userPlatformCommands, manager, "enable", target); err == nil {
		enabledBeforeBootstrap = true
	} else if !isLaunchctlNotLoaded(err) {
		return fmt.Errorf("wire-connect: enable user LaunchAgent %q: %w", cfg.Name, err)
	}
	if err := runCommand(ctx, userPlatformCommands, manager, "bootstrap", fmt.Sprintf("gui/%d", darwinUserUID()), plist); err != nil {
		return fmt.Errorf("wire-connect: bootstrap user LaunchAgent %q: %w", cfg.Name, err)
	}
	if !enabledBeforeBootstrap {
		if err := runCommand(ctx, userPlatformCommands, manager, "enable", target); err != nil {
			return fmt.Errorf("wire-connect: enable user LaunchAgent %q: %w", cfg.Name, err)
		}
	}
	if err := runCommand(ctx, userPlatformCommands, manager, "kickstart", "-k", target); err != nil {
		return fmt.Errorf("wire-connect: start user LaunchAgent %q: %w", cfg.Name, err)
	}
	return nil
}

func darwinUserStop(ctx context.Context, name string) error {
	hasRecord, err := darwinUserPlistExists(name)
	if err != nil {
		return err
	}
	if !hasRecord {
		return fmt.Errorf("%w: %q", ErrNotInstalled, name)
	}
	manager, err := darwinUserLaunchctl()
	if err != nil {
		return err
	}
	target := darwinUserTarget(name)
	// Disable is intentionally done before bootout. launchd persists that
	// override, preventing KeepAlive/RunAtLoad from bringing the process back.
	if err := runCommand(ctx, userPlatformCommands, manager, "disable", target); err != nil && !isLaunchctlNotLoaded(err) {
		return fmt.Errorf("wire-connect: disable user LaunchAgent %q: %w", name, err)
	}
	if err := runCommand(ctx, userPlatformCommands, manager, "bootout", target); err != nil && !isLaunchctlNotLoaded(err) {
		return fmt.Errorf("wire-connect: stop user LaunchAgent %q: %w", name, err)
	}
	return nil
}

func darwinUserUninstall(ctx context.Context, name string) error {
	plist, err := darwinUserPlistPath(name)
	if err != nil {
		return err
	}
	installedDir, err := darwinUserInstalledDir(name)
	if err != nil {
		return err
	}
	hasRecord, err := darwinUserPlistExists(name)
	if err != nil {
		return err
	}
	hasProgram, err := userDirectoryExists(installedDir)
	if err != nil {
		return err
	}
	if !hasRecord && !hasProgram {
		return nil
	}
	manager, err := darwinUserLaunchctl()
	if err != nil {
		return err
	}
	target := darwinUserTarget(name)
	if hasRecord {
		if err := runCommand(ctx, userPlatformCommands, manager, "disable", target); err != nil && !isLaunchctlNotLoaded(err) {
			return fmt.Errorf("wire-connect: disable user LaunchAgent before uninstall: %w", err)
		}
		if err := runCommand(ctx, userPlatformCommands, manager, "bootout", target); err != nil && !isLaunchctlNotLoaded(err) {
			return fmt.Errorf("wire-connect: stop user LaunchAgent before uninstall: %w", err)
		}
	}
	if err := userRemoveFile(plist); err != nil {
		return fmt.Errorf("wire-connect: remove user LaunchAgent plist: %w", err)
	}
	if err := userRemoveDir(installedDir); err != nil {
		return fmt.Errorf("wire-connect: remove user executable: %w", err)
	}
	return nil
}

func darwinUserStatus(ctx context.Context, name string) (string, error) {
	hasRecord, err := darwinUserPlistExists(name)
	if err != nil {
		return "", err
	}
	if !hasRecord {
		return "", fmt.Errorf("%w: %q", ErrNotInstalled, name)
	}
	manager, err := darwinUserLaunchctl()
	if err != nil {
		return "", err
	}
	out, runErr := commandOutput(ctx, userPlatformCommands, manager, "print", darwinUserTarget(name))
	if runErr != nil {
		if isLaunchctlNotLoaded(runErr) {
			return "stopped", nil
		}
		return "", fmt.Errorf("wire-connect: query user LaunchAgent %q: %w", name, runErr)
	}
	if state := launchdState(out); state != "" {
		return strings.ToLower(state), nil
	}
	return "loaded", nil
}

func darwinUserCheck(ctx context.Context) error {
	manager, err := darwinUserLaunchctl()
	if err != nil {
		return err
	}
	if err := runCommand(ctx, userPlatformCommands, manager, "print", fmt.Sprintf("gui/%d", darwinUserUID())); err != nil {
		return fmt.Errorf("wire-connect: user launchd session is unavailable: %w", err)
	}
	return nil
}

func darwinUserPlistExists(name string) (bool, error) {
	path, err := darwinUserPlistPath(name)
	if err != nil {
		return false, err
	}
	if err := userValidateExistingAncestors(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("wire-connect: inspect user LaunchAgent plist: %w", err)
	}
	if err := validateUserFile(st, path); err != nil {
		return false, fmt.Errorf("wire-connect: user LaunchAgent plist %q is not safe: %w", path, err)
	}
	return true, nil
}

func darwinUserPlist(cfg normalizedConfig, executable string) []byte {
	args := []string{executable, "resume", "--name", cfg.Name, "--state-dir", cfg.StateDir, "--foreground"}
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	plistKeyString(&b, "Label", darwinUserLabel(cfg.Name))
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, arg := range args {
		b.WriteString("\t\t<string>")
		escapeXML(&b, arg)
		b.WriteString("</string>\n")
	}
	b.WriteString("\t</array>\n")
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	b.WriteString("\t<key>KeepAlive</key>\n\t<true/>\n")
	b.WriteString("\t<key>ProcessType</key>\n\t<string>Background</string>\n")
	b.WriteString("\t<key>ThrottleInterval</key>\n\t<integer>5</integer>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes()
}
