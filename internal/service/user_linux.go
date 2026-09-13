//go:build linux && (amd64 || arm64)

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

var linuxUserSystemctl = findSystemctl
var linuxUserUnitExists = linuxUserServiceRecordExists

func userInstall(ctx context.Context, cfg normalizedConfig) error { return linuxUserInstall(ctx, cfg) }
func userStop(ctx context.Context, name string) error             { return linuxUserStop(ctx, name) }
func userUninstall(ctx context.Context, name string) error        { return linuxUserUninstall(ctx, name) }
func userStatus(ctx context.Context, name string) (string, error) { return linuxUserStatus(ctx, name) }
func userCheck(ctx context.Context) error                         { return linuxUserCheck(ctx) }

func linuxUserNativeName(name string) string {
	return "wire-connect-" + name
}

func linuxUserDataBase(home string) string {
	if candidate := userGetenv("XDG_DATA_HOME"); candidate != "" && filepath.IsAbs(candidate) && userPathWithin(home, candidate) {
		return filepath.Clean(candidate)
	}
	return filepath.Join(home, ".local", "share")
}

func linuxUserConfigBase(home string) string {
	if candidate := userGetenv("XDG_CONFIG_HOME"); candidate != "" && filepath.IsAbs(candidate) && userPathWithin(home, candidate) {
		return filepath.Clean(candidate)
	}
	return filepath.Join(home, ".config")
}

func userInstallBase(home string) string {
	return linuxUserDataBase(home)
}

func linuxUserInstalledDir(name string) (string, error) {
	home, err := userHomeDir()
	if err != nil {
		return "", fmt.Errorf("wire-connect: determine current user home: %w", err)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return "", err
	}
	return filepath.Join(linuxUserDataBase(filepath.Clean(home)), "wire-connect", name), nil
}

func linuxUserInstalledExecutable(name string) (string, error) {
	dir, err := linuxUserInstalledDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wirectl-connect"), nil
}

func linuxUserUnitPath(name string) (string, error) {
	home, err := userHomeDir()
	if err != nil {
		return "", fmt.Errorf("wire-connect: determine current user home: %w", err)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return "", err
	}
	return filepath.Join(linuxUserConfigBase(filepath.Clean(home)), "systemd", "user", linuxUserNativeName(name)+".service"), nil
}

func linuxUserUnit(name string) string {
	return linuxUserNativeName(name) + ".service"
}

func linuxUserInstall(ctx context.Context, cfg normalizedConfig) error {
	installed, err := linuxUserInstalledExecutable(cfg.Name)
	if err != nil {
		return err
	}
	record, err := linuxUserUnitPath(cfg.Name)
	if err != nil {
		return err
	}
	manager, err := linuxUserSystemctl()
	if err != nil {
		return err
	}
	if err := userCopyAtomic(ctx, cfg.Executable, installed); err != nil {
		return fmt.Errorf("wire-connect: install user executable: %w", err)
	}
	if err := userWriteAtomic(ctx, record, linuxUserUnitBytes(cfg, installed), 0600); err != nil {
		return fmt.Errorf("wire-connect: install user systemd unit: %w", err)
	}
	if err := runCommand(ctx, userPlatformCommands, manager, "--user", "daemon-reload"); err != nil {
		return fmt.Errorf("wire-connect: reload user systemd: %w", err)
	}
	if err := runCommand(ctx, userPlatformCommands, manager, "--user", "enable", linuxUserUnit(cfg.Name)); err != nil {
		return fmt.Errorf("wire-connect: enable user systemd service %q: %w", cfg.Name, err)
	}
	// restart starts an inactive unit and reexecutes an active unit, so a
	// package upgrade cannot leave an old executable image in memory.
	if err := runCommand(ctx, userPlatformCommands, manager, "--user", "restart", linuxUserUnit(cfg.Name)); err != nil {
		return fmt.Errorf("wire-connect: start or restart user systemd service %q: %w", cfg.Name, err)
	}
	return nil
}

func linuxUserStop(ctx context.Context, name string) error {
	installed, err := linuxUserUnitExists(name)
	if err != nil {
		return err
	}
	if !installed {
		return fmt.Errorf("%w: %q", ErrNotInstalled, name)
	}
	manager, err := linuxUserSystemctl()
	if err != nil {
		return err
	}
	if err := runCommand(ctx, userPlatformCommands, manager, "--user", "disable", "--now", linuxUserUnit(name)); err != nil {
		if isSystemdNotInstalled(err) {
			return fmt.Errorf("%w: %q", ErrNotInstalled, name)
		}
		return fmt.Errorf("wire-connect: stop and disable user systemd service %q: %w", name, err)
	}
	return nil
}

func linuxUserUninstall(ctx context.Context, name string) error {
	record, err := linuxUserUnitPath(name)
	if err != nil {
		return err
	}
	installedDir, err := linuxUserInstalledDir(name)
	if err != nil {
		return err
	}
	hasRecord, err := linuxUserUnitExists(name)
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
	manager, err := linuxUserSystemctl()
	if err != nil {
		return err
	}
	if hasRecord {
		if err := runCommand(ctx, userPlatformCommands, manager, "--user", "disable", "--now", linuxUserUnit(name)); err != nil && !isSystemdNotInstalled(err) {
			return fmt.Errorf("wire-connect: stop user systemd service before uninstall: %w", err)
		}
		if err := runCommand(ctx, userPlatformCommands, manager, "--user", "daemon-reload"); err != nil {
			return fmt.Errorf("wire-connect: reload user systemd before uninstall: %w", err)
		}
	}
	if err := userRemoveFile(record); err != nil {
		return fmt.Errorf("wire-connect: remove user systemd unit: %w", err)
	}
	if hasRecord {
		if err := runCommand(ctx, userPlatformCommands, manager, "--user", "daemon-reload"); err != nil {
			return fmt.Errorf("wire-connect: reload user systemd after uninstall: %w", err)
		}
	}
	if err := userRemoveDir(installedDir); err != nil {
		return fmt.Errorf("wire-connect: remove user executable: %w", err)
	}
	return nil
}

func linuxUserStatus(ctx context.Context, name string) (string, error) {
	hasRecord, err := linuxUserUnitExists(name)
	if err != nil {
		return "", err
	}
	if !hasRecord {
		return "", fmt.Errorf("%w: %q", ErrNotInstalled, name)
	}
	manager, err := linuxUserSystemctl()
	if err != nil {
		return "", err
	}
	out, runErr := commandOutput(ctx, userPlatformCommands, manager, "--user", "is-active", linuxUserUnit(name))
	status := firstLine(out)
	if status != "" && (runErr == nil || isSystemdState(status)) {
		return status, nil
	}
	if runErr != nil {
		if isSystemdNotInstalled(runErr) {
			return "", fmt.Errorf("%w: %q", ErrNotInstalled, name)
		}
		return status, fmt.Errorf("wire-connect: query user systemd service %q: %w", name, runErr)
	}
	return "", errors.New("wire-connect: user systemd returned an empty service state")
}

func linuxUserCheck(ctx context.Context) error {
	manager, err := linuxUserSystemctl()
	if err != nil {
		return err
	}
	if err := runCommand(ctx, userPlatformCommands, manager, "--user", "show-environment"); err != nil {
		return fmt.Errorf("wire-connect: user systemd session is unavailable: %w", err)
	}
	return nil
}

func linuxUserServiceRecordExists(name string) (bool, error) {
	path, err := linuxUserUnitPath(name)
	if err != nil {
		return false, err
	}
	if err := userValidateExistingAncestors(path); err != nil {
		// A missing parent means the record is absent. Avoid making status and
		// stop create a user systemd directory just to report that fact.
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
		return false, fmt.Errorf("wire-connect: inspect user systemd unit: %w", err)
	}
	if err := validateUserFile(st, path); err != nil {
		return false, fmt.Errorf("wire-connect: user systemd unit %q is not safe: %w", path, err)
	}
	return true, nil
}

func userPathWithin(base, candidate string) bool {
	base, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(candidate))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func linuxUserUnitBytes(cfg normalizedConfig, executable string) []byte {
	args := []string{"resume", "--name", cfg.Name, "--state-dir", cfg.StateDir, "--foreground"}
	var b bytes.Buffer
	b.WriteString("[Unit]\n")
	b.WriteString("Description=wire-connect user connection (" + cfg.Name + ")\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("After=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=")
	command := append([]string{executable}, args...)
	for i, arg := range command {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(systemdQuote(arg))
	}
	b.WriteString("\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=2s\n")
	b.WriteString("TimeoutStopSec=30s\n")
	b.WriteString("KillSignal=SIGTERM\n")
	b.WriteString("UMask=0077\n")
	b.WriteString("NoNewPrivileges=true\n\n")
	b.WriteString("[Install]\nWantedBy=default.target\n")
	return b.Bytes()
}
