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

const linuxSystemdDir = "/etc/systemd/system"

var (
	platformCommands commandRunner = execCommandRunner{}
	linuxSystemctl                 = findSystemctl
	linuxRequireRoot               = requireUnixRoot
)

func linuxNativeName(name string) string {
	return "wire-connect-" + name
}

func linuxUnitPath(name string) string {
	return filepath.Join(linuxSystemdDir, linuxNativeName(name)+".service")
}

func linuxInstalledDir(name string) string {
	return filepath.Join(unixInstallRoot, name)
}

func linuxInstalledExecutable(name string) string {
	return filepath.Join(linuxInstalledDir(name), "wirectl-connect")
}

// Install copies the executable into a root-owned directory, writes one
// systemd unit for the selected profile, reloads systemd, and starts it.
func Install(ctx context.Context, cfg Config) error {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := linuxRequireRoot(); err != nil {
		return err
	}
	manager, err := linuxSystemctl()
	if err != nil {
		return err
	}
	if platformFiles == nil {
		return errors.New("wire-connect: nil platform file operator")
	}
	if err := platformFiles.ValidateStateDir(ctx, normalized.StateDir); err != nil {
		return err
	}

	installed := linuxInstalledExecutable(normalized.Name)
	if err := platformFiles.CopyProtected(ctx, normalized.Executable, installed); err != nil {
		return fmt.Errorf("wire-connect: install executable: %w", err)
	}
	if err := platformFiles.WriteProtected(ctx, linuxUnitPath(normalized.Name), linuxUnit(normalized), 0644); err != nil {
		return fmt.Errorf("wire-connect: install systemd unit: %w", err)
	}
	if err := runCommand(ctx, platformCommands, manager, "daemon-reload"); err != nil {
		return fmt.Errorf("wire-connect: reload systemd: %w", err)
	}
	if err := runCommand(ctx, platformCommands, manager, "enable", linuxNativeName(normalized.Name)+".service"); err != nil {
		return fmt.Errorf("wire-connect: enable systemd service %q: %w", normalized.Name, err)
	}
	// Restart also handles upgrades: replacing the on-disk executable does not
	// change the image of an already running Linux process.
	if err := runCommand(ctx, platformCommands, manager, "restart", linuxNativeName(normalized.Name)+".service"); err != nil {
		return fmt.Errorf("wire-connect: start or restart systemd service %q: %w", normalized.Name, err)
	}
	return nil
}

// Stop stops the service and disables its boot-time activation.  The unit,
// executable, and state directory remain available for a later Install.
func Stop(ctx context.Context, name string) error {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := linuxRequireRoot(); err != nil {
		return err
	}
	manager, err := linuxSystemctl()
	if err != nil {
		return err
	}
	if err := runCommand(ctx, platformCommands, manager, "disable", "--now", linuxNativeName(normalizedName)+".service"); err != nil {
		if isSystemdNotInstalled(err) {
			return fmt.Errorf("%w: %q", ErrNotInstalled, normalizedName)
		}
		return fmt.Errorf("wire-connect: stop and disable systemd service %q: %w", normalizedName, err)
	}
	return nil
}

// Uninstall removes the systemd unit and the package-owned executable copy.
// It deliberately leaves the caller's state directory, profiles, and
// credentials untouched.
func Uninstall(ctx context.Context, name string) error {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := linuxRequireRoot(); err != nil {
		return err
	}
	manager, err := linuxSystemctl()
	if err != nil {
		return err
	}
	if err := runCommand(ctx, platformCommands, manager, "disable", "--now", linuxNativeName(normalizedName)+".service"); err != nil && !isSystemdNotInstalled(err) {
		return fmt.Errorf("wire-connect: stop systemd service before uninstall: %w", err)
	}
	if err := runCommand(ctx, platformCommands, manager, "daemon-reload"); err != nil {
		return fmt.Errorf("wire-connect: reload systemd before uninstall: %w", err)
	}
	if platformFiles == nil {
		return errors.New("wire-connect: nil platform file operator")
	}
	if err := platformFiles.RemoveFile(ctx, linuxUnitPath(normalizedName)); err != nil {
		return fmt.Errorf("wire-connect: remove systemd unit: %w", err)
	}
	if err := runCommand(ctx, platformCommands, manager, "daemon-reload"); err != nil {
		return fmt.Errorf("wire-connect: reload systemd after uninstall: %w", err)
	}
	if err := platformFiles.RemoveDir(ctx, linuxInstalledDir(normalizedName)); err != nil {
		return fmt.Errorf("wire-connect: remove installed executable: %w", err)
	}
	return nil
}

// Status returns systemd's native active-state string (for example active,
// inactive, or failed).  Inactive states are valid status results and do not
// become errors merely because systemctl uses a non-zero exit code for them.
func Status(ctx context.Context, name string) (string, error) {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return "", err
	}
	if err := contextErr(ctx); err != nil {
		return "", err
	}
	manager, err := linuxSystemctl()
	if err != nil {
		return "", err
	}
	out, runErr := commandOutput(ctx, platformCommands, manager, "is-active", linuxNativeName(normalizedName)+".service")
	status := firstLine(out)
	if status != "" && (runErr == nil || isSystemdState(status)) {
		return status, nil
	}
	if runErr != nil {
		return status, fmt.Errorf("wire-connect: query systemd service %q: %w", normalizedName, runErr)
	}
	return "", errors.New("wire-connect: systemd returned an empty service state")
}

func findSystemctl() (string, error) {
	for _, candidate := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		st, err := os.Stat(candidate)
		if err == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0 {
			return candidate, nil
		}
	}
	return "", errors.New("wire-connect: systemctl was not found at /usr/bin/systemctl or /bin/systemctl")
}

func firstLine(out []byte) string {
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	return line
}

func isSystemdState(status string) bool {
	switch status {
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
	for _, phrase := range []string{"unit .* not found", "unit .* not loaded", "not loaded", "could not be found", "does not exist", "not found"} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}

func linuxUnit(cfg normalizedConfig) []byte {
	var b bytes.Buffer
	b.WriteString("[Unit]\n")
	b.WriteString("Description=wire-connect (" + cfg.Name + ")\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("After=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=")
	args := append([]string{linuxInstalledExecutable(cfg.Name)}, serviceArgs(cfg)...)
	for i, arg := range args {
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
	b.WriteString("CapabilityBoundingSet=CAP_NET_ADMIN\n")
	b.WriteString("AmbientCapabilities=CAP_NET_ADMIN\n")
	b.WriteString("NoNewPrivileges=true\n\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.Bytes()
}

// systemdQuote emits one argument in systemd.exec's quoted argument syntax.
// It does not use shell quoting: the generated unit is parsed directly by
// systemd and every caller-controlled byte is escaped where needed.
func systemdQuote(value string) string {
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('"')
	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteByte(c)
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
