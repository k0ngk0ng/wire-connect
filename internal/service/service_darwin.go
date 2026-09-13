//go:build darwin && (amd64 || arm64)

package service

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

const launchdDir = "/Library/LaunchDaemons"

var (
	platformCommands    commandRunner = execCommandRunner{}
	darwinLaunchctl                   = findLaunchctl
	darwinRequireRoot                 = requireUnixRoot
	darwinPlistExists                 = darwinServiceRecordExists
	darwinProgramExists               = darwinInstalledDirExists
)

func darwinNativeName(name string) string {
	return "com.k0ngk0ng.wire-connect." + name
}

func darwinTarget(name string) string {
	return "system/" + darwinNativeName(name)
}

func darwinPlistPath(name string) string {
	return filepath.Join(launchdDir, darwinNativeName(name)+".plist")
}

func darwinInstalledDir(name string) string {
	return filepath.Join(unixInstallRoot, name)
}

func darwinInstalledExecutable(name string) string {
	return filepath.Join(darwinInstalledDir(name), "wirectl-connect")
}

// Install copies the executable into a root-owned directory and registers a
// LaunchDaemon for the selected profile.  ProgramArguments is emitted as an
// XML array, so no shell or command-line re-parsing is involved.
func Install(ctx context.Context, cfg Config) error {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := darwinRequireRoot(); err != nil {
		return err
	}
	manager, err := darwinLaunchctl()
	if err != nil {
		return err
	}
	if platformFiles == nil {
		return errors.New("wire-connect: nil platform file operator")
	}
	if err := platformFiles.ValidateStateDir(ctx, normalized.StateDir); err != nil {
		return err
	}
	if err := platformFiles.CopyProtected(ctx, normalized.Executable, darwinInstalledExecutable(normalized.Name)); err != nil {
		return fmt.Errorf("wire-connect: install executable: %w", err)
	}
	if err := platformFiles.WriteProtected(ctx, darwinPlistPath(normalized.Name), darwinPlist(normalized), 0644); err != nil {
		return fmt.Errorf("wire-connect: install LaunchDaemon plist: %w", err)
	}

	target := darwinTarget(normalized.Name)
	// Clear a persistent disabled override before loading a replacement job.
	// launchctl may reject bootstrap for a previously disabled label. On a
	// first install the label is not loaded yet, so defer that harmless
	// "not loaded" result and retry enable after bootstrap.
	enabledBeforeBootstrap := false
	if err := runCommand(ctx, platformCommands, manager, "enable", target); err == nil {
		enabledBeforeBootstrap = true
	} else if !isLaunchctlNotLoaded(err) {
		return fmt.Errorf("wire-connect: enable LaunchDaemon %q: %w", normalized.Name, err)
	}
	if err := runCommand(ctx, platformCommands, manager, "bootstrap", "system", darwinPlistPath(normalized.Name)); err != nil {
		// A previous installation may still be bootstrapped.  Unload only after
		// bootstrap reports an error, then retry with the new plist.
		if unloadErr := runCommand(ctx, platformCommands, manager, "bootout", target); unloadErr != nil {
			return fmt.Errorf("wire-connect: bootstrap LaunchDaemon %q: %w (also failed to replace existing job: %v)", normalized.Name, err, unloadErr)
		}
		if retryErr := runCommand(ctx, platformCommands, manager, "bootstrap", "system", darwinPlistPath(normalized.Name)); retryErr != nil {
			return fmt.Errorf("wire-connect: bootstrap LaunchDaemon %q after replacement: %w", normalized.Name, retryErr)
		}
	}
	if !enabledBeforeBootstrap {
		if err := runCommand(ctx, platformCommands, manager, "enable", target); err != nil {
			return fmt.Errorf("wire-connect: enable LaunchDaemon %q: %w", normalized.Name, err)
		}
	}
	if err := runCommand(ctx, platformCommands, manager, "kickstart", "-k", target); err != nil {
		return fmt.Errorf("wire-connect: start LaunchDaemon %q: %w", normalized.Name, err)
	}
	return nil
}

// Stop terminates the LaunchDaemon and persists a disabled state.  The plist,
// installed executable, and user state remain in place.
func Stop(ctx context.Context, name string) error {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	plistInstalled, err := darwinPlistExists(normalizedName)
	if err != nil {
		return err
	}
	if !plistInstalled {
		return fmt.Errorf("%w: %q", ErrNotInstalled, normalizedName)
	}
	if err := darwinRequireRoot(); err != nil {
		return err
	}
	manager, err := darwinLaunchctl()
	if err != nil {
		return err
	}
	target := darwinTarget(normalizedName)
	loaded, err := launchdLoaded(ctx, manager, target)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect LaunchDaemon %q: %w", normalizedName, err)
	}
	if err := runCommand(ctx, platformCommands, manager, "disable", target); err != nil {
		if isLaunchctlNotLoaded(err) {
			// The plist is still installed, so a missing launchd job is an
			// already-stopped service rather than an absent installation. Keep
			// the idempotent Stop contract while retaining the disabled state.
		} else {
			return fmt.Errorf("wire-connect: disable LaunchDaemon %q: %w", normalizedName, err)
		}
	}
	if !loaded {
		return nil
	}
	if err := runCommand(ctx, platformCommands, manager, "kill", "SIGTERM", target); err != nil && !isLaunchctlNotLoaded(err) {
		return fmt.Errorf("wire-connect: stop LaunchDaemon %q: %w", normalizedName, err)
	}
	if err := runCommand(ctx, platformCommands, manager, "bootout", target); err != nil && !isLaunchctlNotLoaded(err) {
		return fmt.Errorf("wire-connect: unload LaunchDaemon %q: %w", normalizedName, err)
	}
	return nil
}

// Uninstall removes the LaunchDaemon registration, plist, and package-owned
// executable.  It never removes the configured state directory.
func Uninstall(ctx context.Context, name string) error {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	plistInstalled, err := darwinPlistExists(normalizedName)
	if err != nil {
		return err
	}
	programInstalled, err := darwinProgramExists(normalizedName)
	if err != nil {
		return err
	}
	if !plistInstalled && !programInstalled {
		return nil
	}
	if err := darwinRequireRoot(); err != nil {
		return err
	}
	manager, err := darwinLaunchctl()
	if err != nil {
		return err
	}
	target := darwinTarget(normalizedName)
	loaded, err := launchdLoaded(ctx, manager, target)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect LaunchDaemon before uninstall: %w", err)
	}
	if loaded {
		if err := runCommand(ctx, platformCommands, manager, "disable", target); err != nil && !isLaunchctlNotLoaded(err) {
			return fmt.Errorf("wire-connect: disable LaunchDaemon before uninstall: %w", err)
		}
		if err := runCommand(ctx, platformCommands, manager, "kill", "SIGTERM", target); err != nil && !isLaunchctlNotLoaded(err) {
			return fmt.Errorf("wire-connect: stop LaunchDaemon before uninstall: %w", err)
		}
		if err := runCommand(ctx, platformCommands, manager, "bootout", target); err != nil && !isLaunchctlNotLoaded(err) {
			return fmt.Errorf("wire-connect: unload LaunchDaemon %q: %w", normalizedName, err)
		}
	}
	// Clear launchd's persistent disabled override before deleting the record.
	if err := runCommand(ctx, platformCommands, manager, "enable", target); err != nil && !isLaunchctlNotLoaded(err) {
		return fmt.Errorf("wire-connect: clear LaunchDaemon disabled state %q: %w", normalizedName, err)
	}
	if platformFiles == nil {
		return errors.New("wire-connect: nil platform file operator")
	}
	if err := platformFiles.RemoveFile(ctx, darwinPlistPath(normalizedName)); err != nil {
		return fmt.Errorf("wire-connect: remove LaunchDaemon plist: %w", err)
	}
	if err := platformFiles.RemoveDir(ctx, darwinInstalledDir(normalizedName)); err != nil {
		return fmt.Errorf("wire-connect: remove installed executable: %w", err)
	}
	return nil
}

// Status returns launchd's native state field, normally running or exited.
// An unloaded job is reported as stopped so status remains useful after Stop.
func Status(ctx context.Context, name string) (string, error) {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return "", err
	}
	if err := contextErr(ctx); err != nil {
		return "", err
	}
	manager, err := darwinLaunchctl()
	if err != nil {
		return "", err
	}
	out, runErr := commandOutput(ctx, platformCommands, manager, "print", darwinTarget(normalizedName))
	if runErr != nil {
		if isLaunchctlNotLoaded(runErr) {
			return "stopped", nil
		}
		return "", fmt.Errorf("wire-connect: query LaunchDaemon %q: %w", normalizedName, runErr)
	}
	if state := launchdState(out); state != "" {
		return state, nil
	}
	return "loaded", nil
}

func findLaunchctl() (string, error) {
	for _, candidate := range []string{"/bin/launchctl", "/usr/bin/launchctl"} {
		st, err := os.Stat(candidate)
		if err == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0 {
			return candidate, nil
		}
	}
	return "", errors.New("wire-connect: launchctl was not found at /bin/launchctl or /usr/bin/launchctl")
}

func darwinServiceRecordExists(name string) (bool, error) {
	path := darwinPlistPath(name)
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("wire-connect: inspect LaunchDaemon record: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return false, fmt.Errorf("wire-connect: LaunchDaemon record %q is not a regular file", path)
	}
	return true, nil
}

func darwinInstalledDirExists(name string) (bool, error) {
	path := darwinInstalledDir(name)
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("wire-connect: inspect installed service directory: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return false, fmt.Errorf("wire-connect: installed service directory %q is not a real directory", path)
	}
	return true, nil
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

func launchdLoaded(ctx context.Context, manager, target string) (bool, error) {
	_, err := commandOutput(ctx, platformCommands, manager, "print", target)
	if err == nil {
		return true, nil
	}
	if isLaunchctlNotLoaded(err) {
		return false, nil
	}
	return false, err
}

func isLaunchctlNotLoaded(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, phrase := range []string{"could not find service", "no such process", "service is not loaded", "service not found", "domain does not support specified action"} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}

func darwinPlist(cfg normalizedConfig) []byte {
	args := append([]string{darwinInstalledExecutable(cfg.Name)}, serviceArgs(cfg)...)
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	plistKeyString(&b, "Label", darwinNativeName(cfg.Name))
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

func plistKeyString(b *bytes.Buffer, key, value string) {
	b.WriteString("\t<key>")
	escapeXML(b, key)
	b.WriteString("</key>\n\t<string>")
	escapeXML(b, value)
	b.WriteString("</string>\n")
}

func escapeXML(b *bytes.Buffer, value string) {
	_ = xml.EscapeText(b, []byte(value))
}
