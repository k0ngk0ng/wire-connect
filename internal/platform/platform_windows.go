//go:build windows && amd64

package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

func validatePlatformName(string) error {
	return nil
}

func openPlatform(ctx context.Context, cfg Config) (tun.Device, func() error, error) {
	if err := ensureInterfaceAbsent(cfg.Name); err != nil {
		return nil, nil, err
	}
	netsh, err := windowsSystemBinary("netsh.exe")
	if err != nil {
		return nil, nil, fmt.Errorf("wire-connect: locate netsh.exe: %w", err)
	}
	device, cleanup, err := openWithPlan(ctx, cfg, tun.CreateTUN, execRunner{}, func(runner commandRunner, name string, config Config) setupPlan {
		return windowsSetupPlanWithBinary(runner, netsh, name, config)
	})
	if err != nil {
		return nil, nil, err
	}
	// netsh can return while Windows still considers the address tentative.
	// Report the TUN ready only after applications can bind its IPv4 address.
	err = waitWindowsIPv4Ready(ctx, func() error {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(cfg.Local.AsSlice())})
		if err != nil {
			return err
		}
		return conn.Close()
	})
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("wire-connect: wait for local IPv4 address %s: %w", cfg.Local, err), cleanup())
	}
	return device, cleanup, nil
}

func waitWindowsIPv4Ready(ctx context.Context, probe func() error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := probe()
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.WSAEADDRNOTAVAIL) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func checkPlatform(ctx context.Context) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	var errs []error
	if _, err := windowsSystemBinary("netsh.exe"); err != nil {
		errs = append(errs, fmt.Errorf("wire-connect: netsh.exe is required to configure the tunnel: %w", err))
	}
	if _, err := windowsSystemBinary("WindowsPowerShell", "v1.0", "powershell.exe"); err != nil {
		errs = append(errs, fmt.Errorf("wire-connect: Windows PowerShell is required to inspect routes: %w", err))
	}
	if err := checkWintunDLL(); err != nil {
		errs = append(errs, err)
	}
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		errs = append(errs, fmt.Errorf("wire-connect: inspect Windows elevation: %w", err))
	} else {
		defer token.Close()
		if !token.IsElevated() {
			errs = append(errs, errors.New("wire-connect: an elevated administrator process is required to configure a Wintun interface"))
		}
	}
	return errors.Join(errs...)
}

func availablePlatform(ctx context.Context, ips []netip.Addr) error {
	powershell, err := windowsSystemBinary("WindowsPowerShell", "v1.0", "powershell.exe")
	if err != nil {
		return fmt.Errorf("wire-connect: locate PowerShell for route inspection: %w", err)
	}
	const script = "$ErrorActionPreference='Stop'; Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Select-Object -Property DestinationPrefix | ConvertTo-Json -Compress"
	output, err := (execRunner{}).Output(ctx, powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect Windows IPv4 routes: %w", err)
	}
	routes, err := parseWindowsRoutePrefixes(output)
	if err != nil {
		return fmt.Errorf("wire-connect: inspect Windows IPv4 routes: %w", err)
	}
	return checkCandidateRoutes(ips, routes)
}

// checkWintunDLL checks only the executable directory.  The Wintun package's
// lazy loader uses LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
// LOAD_LIBRARY_SEARCH_SYSTEM32, so the adjacent release DLL is the only
// application supplied location accepted here; the current working directory
// is intentionally never considered.
func checkWintunDLL() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("wire-connect: determine executable directory for wintun.dll: %w", err)
	}
	candidate := filepath.Join(filepath.Dir(executable), "wintun.dll")
	info, err := os.Stat(candidate)
	if err != nil {
		return fmt.Errorf("wire-connect: wintun.dll was not found beside the executable (%s); install the official Wintun runtime: %w", candidate, err)
	}
	if info.IsDir() {
		return fmt.Errorf("wire-connect: wintun.dll path is a directory: %s", candidate)
	}
	const loaderFlags = windows.LOAD_LIBRARY_SEARCH_APPLICATION_DIR | windows.LOAD_LIBRARY_SEARCH_SYSTEM32
	handle, err := windows.LoadLibraryEx(candidate, 0, loaderFlags)
	if err != nil {
		return fmt.Errorf("wire-connect: load adjacent wintun.dll with the WireGuard loader search policy: %w", err)
	}
	if err := windows.FreeLibrary(handle); err != nil {
		return fmt.Errorf("wire-connect: unload adjacent wintun.dll after validation: %w", err)
	}
	return nil
}

func windowsSystemBinary(parts ...string) (string, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	allParts := append([]string{systemDirectory}, parts...)
	path := filepath.Join(allParts...)
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory", path)
	}
	return path, nil
}

func windowsSetupPlan(runner commandRunner, name string, cfg Config) setupPlan {
	return windowsSetupPlanWithBinary(runner, "netsh.exe", name, cfg)
}

func windowsSetupPlanWithBinary(runner commandRunner, netsh string, name string, cfg Config) setupPlan {
	local := cfg.Local.String()
	peer := cfg.Peer.String() + "/32"
	mtu := fmt.Sprintf("%d", cfg.MTU)
	address := "address=" + local
	mask := "mask=255.255.255.255"
	interfaceArg := "interface=" + name
	nameArg := "name=" + name
	// tun.CreateTUN calls WintunCreateAdapter and NativeTun.Close calls
	// WintunCloseAdapter.  The official Wintun close path owns removal of an
	// adapter created by WintunCreateAdapter; netsh has no generic "delete
	// interface" command, so adapter removal must stay with tun.Device.Close.
	return setupPlan{
		steps: []setupStep{
			commandStep(runner, "enable Wintun interface", netsh,
				[]string{"interface", "set", "interface", nameArg, "admin=enabled"},
				netsh, []string{"interface", "set", "interface", nameArg, "admin=disabled"}),
			commandStep(runner, "set interface MTU", netsh,
				[]string{"interface", "ipv4", "set", "subinterface", interfaceArg, "mtu=" + mtu, "store=active"},
				netsh, []string{"interface", "ipv4", "set", "subinterface", interfaceArg, "mtu=1500", "store=active"}),
			commandStep(runner, "assign local IPv4 address", netsh,
				[]string{"interface", "ipv4", "add", "address", nameArg, address, mask, "store=active"},
				netsh, []string{"interface", "ipv4", "delete", "address", nameArg, address, "store=active"}),
			commandStep(runner, "add peer host route", netsh,
				[]string{"interface", "ipv4", "add", "route", "prefix=" + peer, interfaceArg, "store=active"},
				netsh, []string{"interface", "ipv4", "delete", "route", "prefix=" + peer, interfaceArg, "store=active"}),
		},
	}
}

func nativePrivileges() bool { return windows.GetCurrentProcessToken().IsElevated() }
