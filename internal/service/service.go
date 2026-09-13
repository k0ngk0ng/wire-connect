// Package service manages the optional long-running connect client.
//
// Installing a service is deliberately explicit.  The service manager runs a
// private copy of the executable from a system-owned directory, while the
// caller supplied state directory is never moved or removed by this package.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Config describes a connect service to install.
//
// Executable is the current wirectl-connect executable.  Install copies it to
// a protected, per-service directory before registering the native service.
// StateDir must already exist and be protected for the service account; the
// installer does not migrate a user's profile or credentials.
type Config struct {
	Executable string
	StateDir   string
	Name       string
}

const defaultName = "default"

// ErrUnsupported is returned on platforms outside the supported client
// matrix: Linux and macOS amd64/arm64, and Windows amd64.
var ErrUnsupported = errors.New("wire-connect: service management is unsupported on this platform")

// ErrNotInstalled indicates that the named operating-system service record
// does not exist.  Stop callers can use errors.Is to distinguish this normal
// condition from a permission or service-manager failure.
var ErrNotInstalled = errors.New("wire-connect: service is not installed")

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type normalizedConfig struct {
	Executable string
	StateDir   string
	Name       string
}

func normalizeName(name string) (string, error) {
	if name == "" {
		return defaultName, nil
	}
	if !validName.MatchString(name) {
		return "", fmt.Errorf("wire-connect: invalid service name %q (use 1-64 ASCII letters, digits, '_' or '-')", name)
	}
	return name, nil
}

func normalizeConfig(cfg Config) (normalizedConfig, error) {
	name, err := normalizeName(cfg.Name)
	if err != nil {
		return normalizedConfig{}, err
	}
	if cfg.Executable == "" {
		return normalizedConfig{}, errors.New("wire-connect: executable path is required")
	}
	if strings.IndexByte(cfg.Executable, 0) >= 0 {
		return normalizedConfig{}, errors.New("wire-connect: executable path contains NUL")
	}
	if cfg.StateDir == "" {
		return normalizedConfig{}, errors.New("wire-connect: state directory is required")
	}
	if strings.IndexByte(cfg.StateDir, 0) >= 0 {
		return normalizedConfig{}, errors.New("wire-connect: state directory contains NUL")
	}
	executable, err := filepath.Abs(cfg.Executable)
	if err != nil {
		return normalizedConfig{}, fmt.Errorf("wire-connect: resolve executable path: %w", err)
	}
	stateDir, err := filepath.Abs(cfg.StateDir)
	if err != nil {
		return normalizedConfig{}, fmt.Errorf("wire-connect: resolve state directory: %w", err)
	}
	if !filepath.IsAbs(executable) || !filepath.IsAbs(stateDir) {
		return normalizedConfig{}, errors.New("wire-connect: executable and state directory must resolve to absolute paths")
	}
	return normalizedConfig{Executable: filepath.Clean(executable), StateDir: filepath.Clean(stateDir), Name: name}, nil
}

func serviceArgs(cfg normalizedConfig) []string {
	return []string{"resume", "--state-dir", cfg.StateDir, "--name", cfg.Name, "--service"}
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return errors.New("wire-connect: nil context")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// commandRunner is the only process execution boundary used by service
// managers.  Implementations invoke an executable directly; no shell is ever
// involved.  Output is used only for status and useful diagnostics.
type commandRunner interface {
	Run(context.Context, string, ...string) error
	Output(context.Context, string, ...string) ([]byte, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	_, err := (execCommandRunner{}).Output(ctx, name, args...)
	return err
}

func (execCommandRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, nil
	}
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		return out, fmt.Errorf("run %s: %w", formatCommand(name, args), err)
	}
	return out, fmt.Errorf("run %s: %w: %s", formatCommand(name, args), err, detail)
}

func formatCommand(name string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, name)
	for _, arg := range args {
		parts = append(parts, fmt.Sprintf("%q", arg))
	}
	return strings.Join(parts, " ")
}

// fileOperator is the filesystem boundary used by installers.  The default
// implementation performs ownership/ACL checks, writes files atomically and
// only removes the package-owned installation directory.  Tests replace it
// with a recording implementation and never install into a live OS path.
type fileOperator interface {
	ValidateStateDir(context.Context, string) error
	CopyProtected(context.Context, string, string) error
	WriteProtected(context.Context, string, []byte, os.FileMode) error
	RemoveFile(context.Context, string) error
	RemoveDir(context.Context, string) error
}

func runCommand(ctx context.Context, runner commandRunner, name string, args ...string) error {
	if runner == nil {
		return errors.New("wire-connect: nil command runner")
	}
	return runner.Run(ctx, name, args...)
}

func commandOutput(ctx context.Context, runner commandRunner, name string, args ...string) ([]byte, error) {
	if runner == nil {
		return nil, errors.New("wire-connect: nil command runner")
	}
	return runner.Output(ctx, name, args...)
}
