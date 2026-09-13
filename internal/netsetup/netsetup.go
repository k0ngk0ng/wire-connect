// Package netsetup owns the small privileged helper used to configure the
// local tunnel interface.
//
// The connect process keeps credentials and pairing state in the invoking
// user's profile.  Only the operations which need administrator privileges
// run in the helper.  Ensure starts the same, explicitly validated executable
// through the platform's elevation mechanism when necessary; Install then
// registers a per-user helper whose identity is part of its service name.
package netsetup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Config identifies the executable and user identity for an installed helper.
// Identity is an operating-system identity: a decimal uid on Unix and a
// canonical SID on Windows.  It is deliberately not a username or a value
// read from the environment.
type Config struct {
	Executable string
	Identity   string
}

// Options is the stream-aware form of Ensure.  It is useful to callers which
// want to direct the password prompt and elevation diagnostics to a terminal.
// A nil stream is treated as the corresponding process standard stream by
// EnsureOptions.
type Options struct {
	Executable string
	Identity   string
	In         io.Reader
	Out        io.Writer
	ErrOut     io.Writer
}

// ErrUnsupported is returned on platforms outside the supported client
// matrix: Linux amd64/arm64, macOS arm64, and Windows amd64.
var ErrUnsupported = errors.New("wire-connect: privileged network helper is unsupported on this platform")

// ErrNotInstalled indicates that no helper is registered for an identity.
var ErrNotInstalled = errors.New("wire-connect: privileged network helper is not installed")

// ErrElevationRequired indicates that a privileged operation was requested
// directly without going through Ensure.
var ErrElevationRequired = errors.New("wire-connect: administrator privileges are required")

type normalizedConfig struct {
	Executable string
	Identity   string
}

// These indirections keep the security decisions in the production path
// while allowing tests to exercise Ensure without invoking sudo/UAC or a
// native service manager.
var (
	currentIdentityFn   = currentIdentity
	elevatedFn          = elevated
	requestElevationFn  = requestElevation
	installPlatformFn   = installPlatform
	stopPlatformFn      = stopPlatform
	uninstallPlatformFn = uninstallPlatform
	statusPlatformFn    = statusPlatform
)

func normalizeConfig(cfg Config) (normalizedConfig, error) {
	if cfg.Executable == "" {
		return normalizedConfig{}, errors.New("wire-connect: helper executable path is required")
	}
	if strings.IndexByte(cfg.Executable, 0) >= 0 {
		return normalizedConfig{}, errors.New("wire-connect: helper executable path contains NUL")
	}
	if !filepath.IsAbs(cfg.Executable) {
		return normalizedConfig{}, fmt.Errorf("wire-connect: helper executable path %q must be absolute", cfg.Executable)
	}
	executable := filepath.Clean(cfg.Executable)
	st, err := os.Lstat(executable)
	if err != nil {
		return normalizedConfig{}, fmt.Errorf("wire-connect: inspect helper executable %q: %w", executable, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return normalizedConfig{}, fmt.Errorf("wire-connect: helper executable %q must be a regular file, not a symlink", executable)
	}
	if err := validateExecutablePlatform(st); err != nil {
		return normalizedConfig{}, err
	}

	identity, err := normalizeIdentity(cfg.Identity)
	if err != nil {
		return normalizedConfig{}, err
	}
	return normalizedConfig{Executable: executable, Identity: identity}, nil
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

// CurrentIdentity returns the effective identity of the current process.  It
// never consults an environment variable, username, or caller-provided value.
func CurrentIdentity() (string, error) { return currentIdentityFn() }

// Elevated reports whether the current process has the platform's effective
// administrator privilege.  It is intentionally a boolean because callers
// should use Ensure for the actionable error path.
func Elevated() bool { return elevatedFn() }

// HelperName returns the stable native helper profile name for identity.  The
// name contains no user-controlled bytes and is accepted by systemd,
// launchd, and the Windows SCM.  An invalid identity returns an empty string.
func HelperName(identity string) string {
	identity, err := normalizeIdentity(identity)
	if err != nil {
		return ""
	}
	// Domain-separate the digest so a future use of identity hashes cannot
	// accidentally share service names with this helper.
	h := sha256.Sum256(append([]byte("wire-connect/network-helper/v1\x00"), []byte(identity)...))
	return "helper-" + hex.EncodeToString(h[:16])
}

// NameForIdentity is an explicit alias for callers which prefer a noun over
// HelperName.  Both functions have identical validation and output.
func NameForIdentity(identity string) string { return HelperName(identity) }

func normalizeHelperName(name string) (string, error) {
	if !strings.HasPrefix(name, "helper-") || len(name) != len("helper-")+32 {
		return "", fmt.Errorf("wire-connect: invalid helper name %q", name)
	}
	for _, c := range name[len("helper-"):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf("wire-connect: invalid helper name %q", name)
		}
	}
	return name, nil
}

// Ensure installs and starts the helper for identity.  When the process is
// not elevated, it starts this same executable through sudo/UAC with the
// fixed internal command __setup-network and waits for that process to exit.
// No user state or credentials are read or rewritten by this package.
func Ensure(ctx context.Context, executable, identity string, in io.Reader, out, errOut io.Writer) error {
	return EnsureOptions(ctx, Options{
		Executable: executable,
		Identity:   identity,
		In:         in,
		Out:        out,
		ErrOut:     errOut,
	})
}

// EnsureOptions is the stream-aware implementation of Ensure.
func EnsureOptions(ctx context.Context, opts Options) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	identity := opts.Identity
	if identity == "" {
		var err error
		identity, err = CurrentIdentity()
		if err != nil {
			return err
		}
	}
	normalized, err := normalizeConfig(Config{Executable: opts.Executable, Identity: identity})
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if Elevated() {
		return Install(ctx, Config{Executable: normalized.Executable, Identity: normalized.Identity})
	}

	// A non-elevated caller may only request a helper for its own effective
	// identity.  An explicit different identity is an authorization boundary;
	// accepting it would let an ordinary user target another user's helper.
	current, err := CurrentIdentity()
	if err != nil {
		return err
	}
	if current != normalized.Identity {
		return fmt.Errorf("wire-connect: helper identity %q does not match current identity %q", normalized.Identity, current)
	}
	return requestElevationFn(ctx, normalized.Executable, normalized.Identity, opts.In, opts.Out, opts.ErrOut)
}

// Install registers and starts a root/SYSTEM helper.  It is intended to be
// called by the elevated __setup-network entry point.  An ordinary caller
// should use Ensure so the system's normal authorization UI is shown.
func Install(ctx context.Context, cfg Config) error {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if !Elevated() {
		return ErrElevationRequired
	}
	return installPlatformFn(ctx, normalized)
}

// Stop stops and disables the helper for identity.  This operation requires
// elevation; the setup command is the only place which should invoke it on a
// user's behalf so that no credential state is touched.
func Stop(ctx context.Context, identity string) error {
	normalized, err := normalizeIdentity(identity)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if !Elevated() {
		return ErrElevationRequired
	}
	return stopPlatformFn(ctx, normalized)
}

// Uninstall removes the native helper registration and the package-owned
// executable copy.  The user's state and credentials are outside the package
// installation root and remain untouched.
func Uninstall(ctx context.Context, identity string) error {
	normalized, err := normalizeIdentity(identity)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if !Elevated() {
		return ErrElevationRequired
	}
	return uninstallPlatformFn(ctx, normalized)
}

// Status returns the native service manager state for identity.  A status
// query does not require administrator privileges on supported platforms.
func Status(ctx context.Context, identity string) (string, error) {
	normalized, err := normalizeIdentity(identity)
	if err != nil {
		return "", err
	}
	if err := contextErr(ctx); err != nil {
		return "", err
	}
	return statusPlatformFn(ctx, normalized)
}
