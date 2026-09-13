// Package platform owns the operating-system integration used by connect.
//
// The package deliberately keeps the network configuration small: Open creates
// one WireGuard TUN device, assigns one IPv4 address to it, and installs one
// host route for its peer.  It never changes a default route or DNS settings.
package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/nethelper"
	"golang.zx2c4.com/wireguard/tun"
)

// Config describes the point-to-point network interface to create.
//
// Local and Peer must be IPv4 unicast addresses.  MTU may be zero to select
// DefaultMTU.  Name is an operating-system interface name; it is validated
// before it is passed to either WireGuard or a system networking command.
type Config struct {
	Name  string
	Local netip.Addr
	Peer  netip.Addr
	MTU   int
}

const (
	// DefaultMTU is conservative enough for the encrypted transports used by
	// connect while retaining a useful payload size on ordinary networks.
	DefaultMTU = 1420

	minMTU = 576
	maxMTU = 65535
)

// ErrUnsupported is returned when the current GOOS/GOARCH is outside the
// supported client matrix (Linux and macOS amd64/arm64, Windows amd64).
var ErrUnsupported = errors.New("wire-connect: unsupported platform")

var safeInterfaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,14}$`)

// Open creates and configures a point-to-point TUN device.  The returned
// cleanup function is safe to call more than once and is the caller's
// responsibility to invoke it, normally with a defer immediately after Open.
func Open(ctx context.Context, cfg Config) (tun.Device, func() error, error) {
	if err := contextErr(ctx); err != nil {
		return nil, nil, err
	}

	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	if !nativePrivileges() {
		return nethelper.Open(ctx, nethelper.Config{Name: cfg.Name, Local: cfg.Local.String(), Peer: cfg.Peer.String(), MTU: cfg.MTU})
	}
	if err := checkPlatform(ctx); err != nil {
		return nil, nil, err
	}
	if err := Available(ctx, cfg.Local, cfg.Peer); err != nil {
		return nil, nil, err
	}

	return openPlatform(ctx, cfg)
}

// Check verifies the local prerequisites for Open without creating an
// interface or changing any network state.
func Check(ctx context.Context) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if !nativePrivileges() {
		return nethelper.Check(ctx)
	}
	return checkPlatform(ctx)
}

// Available reports whether every supplied IPv4 address is outside the
// machine's existing non-default IPv4 routes.  It is read-only and is useful
// when selecting a virtual /32 pair before Open is called.  A default route is
// deliberately ignored: an address that is only covered by the default route
// can still be assigned to the point-to-point TUN interface.
func Available(ctx context.Context, ips ...netip.Addr) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if len(ips) == 0 {
		return nil
	}
	for i, ip := range ips {
		if err := validateIPv4(fmt.Sprintf("candidate[%d]", i), ip); err != nil {
			return err
		}
		for j := 0; j < i; j++ {
			if ips[j] == ip {
				return fmt.Errorf("wire-connect: candidate[%d] address %s is duplicated", i, ip)
			}
		}
	}
	return availablePlatform(ctx, ips)
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

func normalizeConfig(cfg Config) (Config, error) {
	if !safeInterfaceName.MatchString(cfg.Name) {
		return Config{}, fmt.Errorf("wire-connect: invalid interface name %q (use 1-15 ASCII letters, digits, '_' or '-')", cfg.Name)
	}
	if err := validatePlatformName(cfg.Name); err != nil {
		return Config{}, err
	}
	if err := validateIPv4("local", cfg.Local); err != nil {
		return Config{}, err
	}
	if err := validateIPv4("peer", cfg.Peer); err != nil {
		return Config{}, err
	}
	if cfg.Local == cfg.Peer {
		return Config{}, errors.New("wire-connect: local and peer addresses must differ")
	}
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.MTU < minMTU || cfg.MTU > maxMTU {
		return Config{}, fmt.Errorf("wire-connect: MTU %d is outside %d-%d", cfg.MTU, minMTU, maxMTU)
	}
	return cfg, nil
}

func validateIPv4(label string, addr netip.Addr) error {
	if !addr.IsValid() || !addr.Is4() {
		return fmt.Errorf("wire-connect: %s address must be a valid IPv4 address", label)
	}
	if addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return fmt.Errorf("wire-connect: %s address %s is not a usable unicast address", label, addr)
	}
	return nil
}

// ensureInterfaceAbsent avoids accidentally reconfiguring an interface owned
// by another process.  The check is inherently subject to a small race with
// another creator; the platform's create call remains the final authority.
func ensureInterfaceAbsent(name string) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("wire-connect: inspect interfaces before creating %q: %w", name, err)
	}
	for _, iface := range interfaces {
		if iface.Name == name {
			return fmt.Errorf("wire-connect: interface %q already exists", name)
		}
	}
	return nil
}

// commandRunner is intentionally tiny so platform setup and rollback can be
// tested with a recording runner.  production code always uses execRunner,
// which executes a binary directly and never invokes a shell.
type commandRunner interface {
	Run(context.Context, string, ...string) error
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) error {
	_, err := (execRunner{}).Output(ctx, name, args...)
	return err
}

func (execRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return output, nil
	}
	detail := strings.TrimSpace(string(output))
	if detail == "" {
		return output, fmt.Errorf("run %s: %w", formatCommand(name, args), err)
	}
	return output, fmt.Errorf("run %s: %w: %s", formatCommand(name, args), err, detail)
}

func formatCommand(name string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, name)
	for _, arg := range args {
		parts = append(parts, fmt.Sprintf("%q", arg))
	}
	return strings.Join(parts, " ")
}

type setupStep struct {
	label string
	apply func(context.Context) error
	undo  func(context.Context) error
}

type cleanupAction struct {
	label string
	fn    func(context.Context) error
}

type setupPlan struct {
	steps   []setupStep
	cleanup []cleanupAction
}

func commandStep(runner commandRunner, label string, applyName string, applyArgs []string, undoName string, undoArgs []string) setupStep {
	return setupStep{
		label: label,
		apply: func(ctx context.Context) error {
			return runner.Run(ctx, applyName, applyArgs...)
		},
		undo: func(ctx context.Context) error {
			return runner.Run(ctx, undoName, undoArgs...)
		},
	}
}

func cleanupCommand(runner commandRunner, label string, name string, args ...string) cleanupAction {
	return cleanupAction{
		label: label,
		fn: func(ctx context.Context) error {
			return runner.Run(ctx, name, args...)
		},
	}
}

// openWithPlan owns the common resource lifecycle.  Platform files only
// describe commands and their inverse commands; this function enforces
// reverse-order rollback, detached cleanup after context cancellation, and
// idempotence.
func openWithPlan(
	ctx context.Context,
	cfg Config,
	create func(string, int) (tun.Device, error),
	runner commandRunner,
	plan func(commandRunner, string, Config) setupPlan,
) (tun.Device, func() error, error) {
	if err := contextErr(ctx); err != nil {
		return nil, nil, err
	}
	if create == nil {
		return nil, nil, errors.New("wire-connect: nil TUN creator")
	}
	if runner == nil {
		return nil, nil, errors.New("wire-connect: nil command runner")
	}
	if plan == nil {
		return nil, nil, errors.New("wire-connect: nil platform setup plan")
	}

	device, err := create(cfg.Name, cfg.MTU)
	if err != nil {
		return nil, nil, fmt.Errorf("wire-connect: create TUN %q: %w", cfg.Name, err)
	}
	if device == nil {
		return nil, nil, errors.New("wire-connect: TUN creator returned a nil device")
	}

	state := newCleanupState(ctx)
	actualName, err := device.Name()
	if err != nil {
		state.push(closeDeviceAction(device))
		stateErr := state.run()
		return nil, nil, errors.Join(fmt.Errorf("wire-connect: get TUN name: %w", err), stateErr)
	}
	if !safeInterfaceName.MatchString(actualName) {
		state.push(closeDeviceAction(device))
		stateErr := state.run()
		return nil, nil, errors.Join(fmt.Errorf("wire-connect: TUN returned unsafe interface name %q", actualName), stateErr)
	}
	if actualName != cfg.Name && !allowDynamicName(cfg.Name, actualName) {
		state.push(closeDeviceAction(device))
		stateErr := state.run()
		return nil, nil, errors.Join(fmt.Errorf("wire-connect: TUN name changed from %q to %q", cfg.Name, actualName), stateErr)
	}

	setup := plan(runner, actualName, cfg)
	// Platform cleanup actions are pushed before the device close action so the
	// device is closed first when cleanup runs in reverse order.  This matters
	// for Wintun, whose adapter cannot be removed while its handle is open.
	for _, action := range setup.cleanup {
		state.push(action)
	}
	state.push(closeDeviceAction(device))

	for _, step := range setup.steps {
		if err := contextErr(ctx); err != nil {
			cleanupErr := state.run()
			return nil, nil, errors.Join(err, cleanupErr)
		}
		if step.apply == nil {
			cleanupErr := state.run()
			return nil, nil, errors.Join(fmt.Errorf("wire-connect: setup step %q has no apply function", step.label), cleanupErr)
		}
		if err := step.apply(ctx); err != nil {
			cleanupErr := state.run()
			return nil, nil, errors.Join(fmt.Errorf("wire-connect: %s: %w", step.label, err), cleanupErr)
		}
		if step.undo != nil {
			state.push(cleanupAction{
				label: "rollback " + step.label,
				fn:    step.undo,
			})
		}
	}

	return device, state.run, nil
}

func allowDynamicName(requested, actual string) bool {
	if requested != "utun" || !strings.HasPrefix(actual, "utun") || !safeInterfaceName.MatchString(actual) || len(actual) == len("utun") {
		return false
	}
	for _, c := range actual[len("utun"):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func closeDeviceAction(device tun.Device) cleanupAction {
	return cleanupAction{
		label: "close TUN device",
		fn: func(context.Context) error {
			return device.Close()
		},
	}
}

type cleanupState struct {
	parent  context.Context
	once    sync.Once
	mu      sync.Mutex
	actions []cleanupAction
	err     error
}

func newCleanupState(parent context.Context) *cleanupState {
	return &cleanupState{parent: parent}
}

func (s *cleanupState) push(action cleanupAction) {
	if action.fn == nil {
		return
	}
	s.mu.Lock()
	s.actions = append(s.actions, action)
	s.mu.Unlock()
}

func (s *cleanupState) run() error {
	s.once.Do(func() {
		base := context.WithoutCancel(s.parent)
		cleanupCtx, cancel := context.WithTimeout(base, 10*time.Second)
		defer cancel()

		s.mu.Lock()
		actions := append([]cleanupAction(nil), s.actions...)
		s.mu.Unlock()

		var errs []error
		for i := len(actions) - 1; i >= 0; i-- {
			if err := actions[i].fn(cleanupCtx); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", actions[i].label, err))
			}
		}
		s.err = errors.Join(errs...)
	})
	return s.err
}
