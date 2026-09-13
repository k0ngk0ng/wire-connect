//go:build linux && (amd64 || arm64)

package platform

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

const linuxTunDevice = "/dev/net/tun"

func validatePlatformName(string) error {
	return nil
}

func openPlatform(ctx context.Context, cfg Config) (tun.Device, func() error, error) {
	if err := ensureInterfaceAbsent(cfg.Name); err != nil {
		return nil, nil, err
	}
	return openWithPlan(ctx, cfg, tun.CreateTUN, execRunner{}, linuxSetupPlan)
}

func checkPlatform(ctx context.Context) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	var errs []error
	if _, err := os.Stat(linuxTunDevice); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("wire-connect: %s is unavailable; load the tun kernel module", linuxTunDevice))
		} else {
			errs = append(errs, fmt.Errorf("wire-connect: inspect %s: %w", linuxTunDevice, err))
		}
	}
	if _, err := exec.LookPath("ip"); err != nil {
		errs = append(errs, fmt.Errorf("wire-connect: ip command is required to configure the tunnel: %w", err))
	}
	if ok, detail := linuxNetAdmin(); !ok {
		errs = append(errs, errors.New("wire-connect: CAP_NET_ADMIN (or root) is required to create and configure a TUN interface"))
		if detail != "" {
			errs = append(errs, fmt.Errorf("wire-connect: permission detail: %s", detail))
		}
	}
	return errors.Join(errs...)
}

func availablePlatform(ctx context.Context, ips []netip.Addr) error {
	output, err := (execRunner{}).Output(ctx, "ip", "-json", "route", "show", "table", "all")
	if err != nil {
		return fmt.Errorf("wire-connect: inspect Linux IPv4 routes: %w", err)
	}
	routes, err := parseLinuxRoutePrefixes(output)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect Linux IPv4 routes: %w", err)
	}
	return checkCandidateRoutes(ips, routes)
}

// linuxNetAdmin accepts root and also checks CapEff for a process that has
// retained CAP_NET_ADMIN without being uid 0.  This keeps Check useful inside
// a capability-scoped container.
func linuxNetAdmin() (bool, string) {
	if os.Geteuid() == 0 {
		return true, ""
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, fmt.Sprintf("effective uid is %d and CapEff is unavailable: %v", os.Geteuid(), err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			break
		}
		value, err := strconv.ParseUint(fields[1], 16, 64)
		if err == nil && value&(uint64(1)<<12) != 0 { // CAP_NET_ADMIN
			return true, ""
		}
		return false, fmt.Sprintf("effective uid is %d and CAP_NET_ADMIN is absent from CapEff", os.Geteuid())
	}
	return false, fmt.Sprintf("effective uid is %d and CapEff is unavailable", os.Geteuid())
}

func linuxSetupPlan(runner commandRunner, name string, cfg Config) setupPlan {
	local := cfg.Local.String() + "/32"
	peer := cfg.Peer.String() + "/32"
	return setupPlan{steps: []setupStep{
		commandStep(runner, "assign local IPv4 address", "ip",
			[]string{"-4", "addr", "add", local, "dev", name},
			"ip", []string{"-4", "addr", "del", local, "dev", name}),
		commandStep(runner, "add peer host route", "ip",
			[]string{"-4", "route", "add", peer, "dev", name},
			"ip", []string{"-4", "route", "del", peer, "dev", name}),
		commandStep(runner, "bring interface up", "ip",
			[]string{"link", "set", "dev", name, "up"},
			"ip", []string{"link", "set", "dev", name, "down"}),
	}}
}
