package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/k0ngk0ng/wire-connect/internal/config"
)

var userGetenv = os.Getenv
var userPlatformCommands commandRunner = execCommandRunner{}

// UserInstall installs and starts a connect client for the current operating
// system user.  Unlike Install, it never talks to a system-wide service
// manager and never needs administrator privileges.  The service manager
// invokes a private executable copy with the current user's credentials.
//
// StateDir is deliberately caller-owned.  It is validated as a private state
// directory before the service record is written, but is never copied or
// removed by this API.
func UserInstall(ctx context.Context, cfg Config) error {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateUserStateDir(normalized.StateDir); err != nil {
		return err
	}
	if err := validateUserSource(normalized.Executable); err != nil {
		return err
	}
	return userInstall(ctx, normalized)
}

// UserStop stops the current user's connect service and disables its native
// automatic start/restart policy.  Installed files and credentials are kept
// so a later UserInstall can resume the saved profile.
func UserStop(ctx context.Context, name string) error {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	return userStop(ctx, normalizedName)
}

// UserUninstall removes the current user's service registration and the
// executable copy owned by that registration.  StateDir, profiles, and
// credentials are intentionally retained; callers that want to forget an
// account must explicitly remove that state through their profile store.
func UserUninstall(ctx context.Context, name string) error {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	return userUninstall(ctx, normalizedName)
}

// UserStatus reports the native current-user service state.  Implementations
// return a stable lower-case state where the platform exposes one.  An absent
// service is reported with ErrNotInstalled so CLI callers can distinguish it
// from a failed service manager.
func UserStatus(ctx context.Context, name string) (string, error) {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return "", err
	}
	if err := contextErr(ctx); err != nil {
		return "", err
	}
	return userStatus(ctx, normalizedName)
}

// UserCheck verifies that the current user's native service manager can be
// contacted. It is intentionally a lightweight preflight: it does not create
// a service record, copy an executable, or require administrator privileges.
// CLI callers should run it before completing an operation that will rely on
// a background service.
func UserCheck(ctx context.Context) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	return userCheck(ctx)
}

// UserServiceArgs is exported for callers and tests that need to inspect the
// exact invocation recorded in a native user service.  It intentionally uses
// --foreground: the service manager owns the process lifetime and the
// process must not recursively install another service.
func UserServiceArgs(name, stateDir string) ([]string, error) {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return nil, err
	}
	if stateDir == "" || strings.IndexByte(stateDir, 0) >= 0 {
		return nil, errors.New("wire-connect: state directory is required and must not contain NUL")
	}
	return []string{"resume", "--name", normalizedName, "--state-dir", stateDir, "--foreground"}, nil
}

// validateUserStateDir uses the same private-state policy as the rest of the
// client.  Store.Init also applies the native Windows ACL policy, which keeps
// the service and the foreground client from silently disagreeing about who
// may read credentials.
func validateUserStateDir(path string) error {
	if path == "" {
		return errors.New("wire-connect: state directory is required")
	}
	if _, err := os.Stat(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("wire-connect: inspect user state directory: %w", err)
	}
	if err := (config.Store{Dir: path}).Init(); err != nil {
		return fmt.Errorf("wire-connect: validate user state directory: %w", err)
	}
	return nil
}
