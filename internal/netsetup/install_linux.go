//go:build linux && (amd64 || arm64)

package netsetup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const linuxSystemdDir = "/etc/systemd/system"

var (
	linuxSystemctlPath  = findLinuxSystemctl
	linuxSystemdDirPath = linuxSystemdDir
	linuxLoginctlPath   = findLinuxLoginctl
)

func installPlatform(ctx context.Context, cfg normalizedConfig) error {
	manager, err := linuxSystemctlPath()
	if err != nil {
		return err
	}
	name := HelperName(cfg.Identity)
	if name == "" {
		return errors.New("wire-connect: could not derive helper name")
	}
	installed := helperExecutable(name)
	if err := copyUnixProtected(ctx, cfg.Executable, installed); err != nil {
		return fmt.Errorf("wire-connect: install network helper executable: %w", err)
	}
	unitPath := filepath.Join(linuxSystemdDirPath, helperUnitName(name)+".service")
	if err := writeUnixRecordProtected(ctx, unitPath, linuxUnit(cfg, name), 0644); err != nil {
		return fmt.Errorf("wire-connect: install network helper systemd unit: %w", err)
	}
	if err := runUnixCommand(ctx, manager, "daemon-reload"); err != nil {
		return fmt.Errorf("wire-connect: reload systemd: %w", err)
	}
	if err := runUnixCommand(ctx, manager, "enable", helperUnitName(name)+".service"); err != nil {
		return fmt.Errorf("wire-connect: enable network helper: %w", err)
	}
	if err := runUnixCommand(ctx, manager, "restart", helperUnitName(name)+".service"); err != nil {
		return fmt.Errorf("wire-connect: start network helper: %w", err)
	}
	// The ordinary connection process is installed as a systemd --user
	// service immediately after setup. Linger keeps that user manager alive
	// after the last SSH/desktop session exits. Never disable linger during
	// uninstall: it may be shared by unrelated user services.
	loginctl, err := linuxLoginctlPath()
	if err != nil {
		return fmt.Errorf("wire-connect: enable persistent user services: %w", err)
	}
	if err := runUnixCommand(ctx, loginctl, "enable-linger", cfg.Identity); err != nil {
		return fmt.Errorf("wire-connect: enable systemd linger for uid %s: %w", cfg.Identity, err)
	}
	return nil
}

func stopPlatform(ctx context.Context, identity string) error {
	manager, err := linuxSystemctlPath()
	if err != nil {
		return err
	}
	name := HelperName(identity)
	if name == "" {
		return errors.New("wire-connect: could not derive helper name")
	}
	unitPath := filepath.Join(linuxSystemdDirPath, helperUnitName(name)+".service")
	unitExists, err := linuxRecordExists(unitPath)
	if err != nil {
		return err
	}
	if !unitExists {
		return fmt.Errorf("%w: %q", ErrNotInstalled, identity)
	}
	if err := runUnixCommand(ctx, manager, "disable", "--now", helperUnitName(name)+".service"); err != nil && !isSystemdNotInstalled(err) {
		return fmt.Errorf("wire-connect: stop network helper: %w", err)
	}
	return nil
}

func uninstallPlatform(ctx context.Context, identity string) error {
	manager, err := linuxSystemctlPath()
	if err != nil {
		return err
	}
	name := HelperName(identity)
	if name == "" {
		return errors.New("wire-connect: could not derive helper name")
	}
	unitPath := filepath.Join(linuxSystemdDirPath, helperUnitName(name)+".service")
	installedDir := helperDir(name)
	unitExists, err := linuxRecordExists(unitPath)
	if err != nil {
		return err
	}
	dirExists, err := linuxRecordExistsAsDir(installedDir)
	if err != nil {
		return err
	}
	if !unitExists && !dirExists {
		return nil
	}
	if err := runUnixCommand(ctx, manager, "disable", "--now", helperUnitName(name)+".service"); err != nil && !isSystemdNotInstalled(err) {
		return fmt.Errorf("wire-connect: stop network helper before uninstall: %w", err)
	}
	if err := runUnixCommand(ctx, manager, "daemon-reload"); err != nil {
		return fmt.Errorf("wire-connect: reload systemd before uninstall: %w", err)
	}
	if unitExists {
		if err := removeUnixRecord(unitPath, linuxSystemdDirPath); err != nil {
			return fmt.Errorf("wire-connect: remove network helper systemd unit: %w", err)
		}
	}
	if err := runUnixCommand(ctx, manager, "daemon-reload"); err != nil {
		return fmt.Errorf("wire-connect: reload systemd after uninstall: %w", err)
	}
	if dirExists {
		if err := removeUnixInstalledDir(installedDir); err != nil {
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
	unitPath := filepath.Join(linuxSystemdDirPath, helperUnitName(name)+".service")
	unitExists, err := linuxRecordExists(unitPath)
	if err != nil {
		return "", err
	}
	if !unitExists {
		return "", fmt.Errorf("%w: %q", ErrNotInstalled, identity)
	}
	manager, err := linuxSystemctlPath()
	if err != nil {
		return "", err
	}
	out, runErr := outputUnixCommand(ctx, manager, "is-active", helperUnitName(name)+".service")
	state := firstUnixLine(out)
	if state != "" && (runErr == nil || isSystemdState(state)) {
		return state, nil
	}
	if runErr != nil {
		return state, fmt.Errorf("wire-connect: query network helper: %w", runErr)
	}
	return "", errors.New("wire-connect: systemd returned an empty network helper state")
}

func findLinuxSystemctl() (string, error) {
	for _, path := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		st, err := os.Lstat(path)
		if err == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", errors.New("wire-connect: systemctl was not found at /usr/bin/systemctl or /bin/systemctl")
}

func findLinuxLoginctl() (string, error) {
	for _, path := range []string{"/usr/bin/loginctl", "/bin/loginctl"} {
		st, err := os.Lstat(path)
		if err == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", errors.New("wire-connect: loginctl was not found at /usr/bin/loginctl or /bin/loginctl; cannot guarantee a persistent user service")
}

func linuxRecordExists(path string) (bool, error) {
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
		return false, fmt.Errorf("wire-connect: helper service record %q is not a regular file", path)
	}
	return true, nil
}

func linuxRecordExistsAsDir(path string) (bool, error) {
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

func linuxUnit(cfg normalizedConfig, name string) []byte {
	var b bytes.Buffer
	b.WriteString("[Unit]\n")
	b.WriteString("Description=wire-connect privileged network helper (" + name + ")\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("After=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("User=root\n")
	b.WriteString("Group=root\n")
	b.WriteString("WorkingDirectory=/\n")
	b.WriteString("Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin\n")
	b.WriteString("Environment=HOME=/\n")
	b.WriteString("ExecStart=")
	args := []string{helperExecutable(name), "__network-helper", "--identity", cfg.Identity, "--name", name}
	for i, arg := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(systemdQuoteUnix(arg))
	}
	b.WriteString("\nRestart=on-failure\nRestartSec=2s\n")
	b.WriteString("TimeoutStopSec=30s\nKillSignal=SIGTERM\nUMask=0077\n")
	b.WriteString("CapabilityBoundingSet=CAP_NET_ADMIN\nAmbientCapabilities=CAP_NET_ADMIN\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("ProtectSystem=full\nPrivateTmp=true\n\n")
	b.WriteString("[Install]\nWantedBy=multi-user.target\n")
	return b.Bytes()
}

func systemdQuoteUnix(value string) string {
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('"')
	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '$':
			b.WriteString("$$")
		case '%':
			b.WriteString("%%")
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if c < 0x20 || c == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func firstUnixLine(out []byte) string {
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	return line
}

func isSystemdState(state string) bool {
	switch state {
	case "active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing", "unknown":
		return true
	default:
		return false
	}
}

func isSystemdNotInstalled(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, phrase := range []string{"not loaded", "could not be found", "does not exist", "not found", "no such file"} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}
