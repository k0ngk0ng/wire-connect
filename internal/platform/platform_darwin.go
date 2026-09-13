//go:build darwin && (amd64 || arm64)

package platform

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

func validatePlatformName(name string) error {
	// utun asks the kernel to allocate the next free unit.  A numbered name is
	// also accepted when a caller needs a stable interface name.
	if name == "utun" {
		return nil
	}
	if len(name) < len("utun5") || name[:4] != "utun" {
		return fmt.Errorf("wire-connect: macOS TUN name must be utun or utunN, got %q", name)
	}
	for _, c := range name[4:] {
		if c < '0' || c > '9' {
			return fmt.Errorf("wire-connect: macOS TUN name must be utun or utunN, got %q", name)
		}
	}
	return nil
}

func openPlatform(ctx context.Context, cfg Config) (tun.Device, func() error, error) {
	// "utun" is a request for a dynamically allocated unit and therefore
	// cannot be checked by name before CreateTUN.  Numbered units can be safely
	// rejected when already present.
	if cfg.Name != "utun" {
		if err := ensureInterfaceAbsent(cfg.Name); err != nil {
			return nil, nil, err
		}
	}
	return openWithPlan(ctx, cfg, tun.CreateTUN, execRunner{}, darwinSetupPlan)
}

func checkPlatform(ctx context.Context) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	var errs []error
	for _, command := range []string{"ifconfig", "netstat"} {
		if _, err := exec.LookPath(command); err != nil {
			errs = append(errs, fmt.Errorf("wire-connect: %s command is required to configure the tunnel: %w", command, err))
		}
	}
	if os.Geteuid() != 0 {
		errs = append(errs, errors.New("wire-connect: administrator privileges are required to configure a macOS TUN interface"))
	}
	return errors.Join(errs...)
}

func availablePlatform(ctx context.Context, ips []netip.Addr) error {
	output, err := (execRunner{}).Output(ctx, "netstat", "-rn", "-f", "inet")
	if err != nil {
		return fmt.Errorf("wire-connect: inspect macOS IPv4 routes: %w", err)
	}
	routes, err := parseDarwinRoutePrefixes(output)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect macOS IPv4 routes: %w", err)
	}
	return checkCandidateRoutes(ips, routes)
}

func darwinSetupPlan(runner commandRunner, name string, cfg Config) setupPlan {
	local := cfg.Local.String()
	peer := cfg.Peer.String()
	return setupPlan{steps: []setupStep{
		// utun is a point-to-point interface: macOS requires the destination
		// address in this ifconfig form and installs the corresponding /32
		// peer route as part of the operation.  Adding the same route again
		// with route(8) fails with EEXIST on current macOS releases.
		commandStep(runner, "assign local and peer IPv4 /32 addresses", "ifconfig",
			[]string{name, "inet", local, peer, "netmask", "255.255.255.255", "up"},
			"ifconfig", []string{name, "inet", local, "-alias"}),
	}}
}
