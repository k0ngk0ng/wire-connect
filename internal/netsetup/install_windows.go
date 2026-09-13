//go:build windows && amd64

package netsetup

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const windowsHelperWait = 30 * time.Second

func windowsNativeHelperServiceName(name string) string {
	// internal/service.Run uses this exact prefix when dispatching a process
	// started by SCM. Keep it in sync so the helper's --name reaches nethelper.
	return "wire-connect-" + name
}

func windowsHelperArgs(cfg normalizedConfig, name string) []string {
	return []string{"__network-helper", "--identity", cfg.Identity, "--name", name}
}

func windowsCommandLine(executable string, args []string) string {
	line := syscall.EscapeArg(executable)
	for _, arg := range args {
		line += " " + syscall.EscapeArg(arg)
	}
	return line
}

func installPlatform(ctx context.Context, cfg normalizedConfig) error {
	name := HelperName(cfg.Identity)
	if name == "" {
		return errors.New("wire-connect: could not derive helper name")
	}
	if err := validateWindowsSource(cfg.Executable); err != nil {
		return err
	}
	sourceWintun := filepath.Join(filepath.Dir(cfg.Executable), "wintun.dll")
	sourceLicense := filepath.Join(filepath.Dir(cfg.Executable), "WINTUN-LICENSE.txt")
	if err := validateWindowsSource(sourceWintun); err != nil {
		return fmt.Errorf("wire-connect: official wintun.dll is required beside executable: %w", err)
	}
	if err := validateWindowsSource(sourceLicense); err != nil {
		return fmt.Errorf("wire-connect: official Wintun license is required beside executable: %w", err)
	}
	installedExecutable, err := windowsHelperExecutable(name)
	if err != nil {
		return err
	}
	installedWintun, err := windowsHelperWintun(name)
	if err != nil {
		return err
	}
	installedLicense, err := windowsHelperLicense(name)
	if err != nil {
		return err
	}
	serviceName := windowsNativeHelperServiceName(name)
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("wire-connect: connect to Windows Service Control Manager: %w", err)
	}
	defer manager.Disconnect()

	service, openErr := manager.OpenService(serviceName)
	created := false
	if openErr != nil {
		if !errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return fmt.Errorf("wire-connect: open network helper service: %w", openErr)
		}
	} else {
		if err := stopWindowsHelper(ctx, service); err != nil {
			_ = service.Close()
			return err
		}
	}
	if err := copyWindowsProtected(ctx, cfg.Executable, installedExecutable); err != nil {
		if service != nil {
			_ = service.Close()
		}
		return fmt.Errorf("wire-connect: install network helper executable: %w", err)
	}
	if err := copyWindowsProtected(ctx, sourceWintun, installedWintun); err != nil {
		if service != nil {
			_ = service.Close()
		}
		return fmt.Errorf("wire-connect: install official wintun.dll: %w", err)
	}
	if err := copyWindowsProtected(ctx, sourceLicense, installedLicense); err != nil {
		if service != nil {
			_ = service.Close()
		}
		return fmt.Errorf("wire-connect: install Wintun license: %w", err)
	}
	args := windowsHelperArgs(cfg, name)
	config := windowsHelperServiceConfig(installedExecutable, args, name)
	if service == nil {
		service, err = manager.CreateService(serviceName, installedExecutable, config, args...)
		if err != nil {
			return fmt.Errorf("wire-connect: create network helper service: %w", err)
		}
		created = true
	}
	defer service.Close()
	if !created {
		if err := service.UpdateConfig(config); err != nil {
			return fmt.Errorf("wire-connect: update network helper service: %w", err)
		}
	}
	if err := service.SetRecoveryActions(windowsHelperRecoveryActions(), 24*60*60); err != nil {
		return fmt.Errorf("wire-connect: configure network helper recovery: %w", err)
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("wire-connect: configure network helper failure recovery: %w", err)
	}
	if err := setWindowsHelperServiceACL(serviceName); err != nil {
		return fmt.Errorf("wire-connect: protect network helper service: %w", err)
	}
	if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("wire-connect: start network helper service: %w", err)
	}
	if err := waitWindowsHelperState(ctx, service, svc.Running); err != nil {
		return fmt.Errorf("wire-connect: wait for network helper service: %w", err)
	}
	return nil
}

func windowsHelperServiceConfig(executable string, args []string, name string) mgr.Config {
	return mgr.Config{
		ServiceType:    windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:      mgr.StartAutomatic,
		ErrorControl:   mgr.ErrorNormal,
		BinaryPathName: windowsCommandLine(executable, args),
		DisplayName:    "wire-connect network helper (" + name + ")",
		Description:    "wire-connect privileged network helper",
		SidType:        windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
}

func windowsHelperRecoveryActions() []mgr.RecoveryAction {
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
}

func setWindowsHelperServiceACL(name string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(name, windows.SE_SERVICE,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

func stopPlatform(ctx context.Context, identity string) error {
	name := HelperName(identity)
	if name == "" {
		return errors.New("wire-connect: could not derive helper name")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("wire-connect: connect to Windows Service Control Manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(windowsNativeHelperServiceName(name))
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fmt.Errorf("%w: %q", ErrNotInstalled, identity)
	}
	if err != nil {
		return fmt.Errorf("wire-connect: open network helper service: %w", err)
	}
	defer service.Close()
	return stopWindowsHelper(ctx, service)
}

func stopWindowsHelper(ctx context.Context, service *mgr.Service) error {
	state, err := service.Query()
	if err != nil {
		return fmt.Errorf("wire-connect: query network helper service: %w", err)
	}
	if state.State != svc.Stopped {
		if _, err := service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return fmt.Errorf("wire-connect: stop network helper service: %w", err)
		}
		if err := waitWindowsHelperState(ctx, service, svc.Stopped); err != nil {
			return fmt.Errorf("wire-connect: wait for network helper service to stop: %w", err)
		}
	}
	config, err := service.Config()
	if err != nil {
		return fmt.Errorf("wire-connect: read network helper service configuration: %w", err)
	}
	config.StartType = mgr.StartDisabled
	if err := service.UpdateConfig(config); err != nil {
		return fmt.Errorf("wire-connect: disable network helper service: %w", err)
	}
	return nil
}

func uninstallPlatform(ctx context.Context, identity string) error {
	name := HelperName(identity)
	if name == "" {
		return errors.New("wire-connect: could not derive helper name")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("wire-connect: connect to Windows Service Control Manager: %w", err)
	}
	serviceName := windowsNativeHelperServiceName(name)
	service, openErr := manager.OpenService(serviceName)
	if openErr == nil {
		if err := stopWindowsHelper(ctx, service); err != nil {
			_ = service.Close()
			_ = manager.Disconnect()
			return err
		}
		if err := service.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			_ = service.Close()
			_ = manager.Disconnect()
			return fmt.Errorf("wire-connect: delete network helper service: %w", err)
		}
		_ = service.Close()
	} else if !errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		_ = manager.Disconnect()
		return fmt.Errorf("wire-connect: open network helper service for uninstall: %w", openErr)
	}
	_ = manager.Disconnect()
	dir, err := windowsHelperDir(name)
	if err != nil {
		return err
	}
	return removeWindowsInstalledDir(dir)
}

func statusPlatform(ctx context.Context, identity string) (string, error) {
	name := HelperName(identity)
	if name == "" {
		return "", errors.New("wire-connect: could not derive helper name")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("wire-connect: connect to Windows Service Control Manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(windowsNativeHelperServiceName(name))
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "", fmt.Errorf("%w: %q", ErrNotInstalled, identity)
	}
	if err != nil {
		return "", fmt.Errorf("wire-connect: open network helper service: %w", err)
	}
	defer service.Close()
	state, err := service.Query()
	if err != nil {
		return "", fmt.Errorf("wire-connect: query network helper service: %w", err)
	}
	return windowsHelperStateName(state.State), nil
}

func waitWindowsHelperState(ctx context.Context, service *mgr.Service, desired svc.State) error {
	deadline := time.Now().Add(windowsHelperWait)
	for {
		if err := contextErr(ctx); err != nil {
			return err
		}
		state, err := service.Query()
		if err != nil {
			return err
		}
		if state.State == desired {
			return nil
		}
		if desired == svc.Running && state.State == svc.Stopped {
			return errors.New("network helper service stopped before reaching running state")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for network helper state %s", windowsHelperStateName(desired))
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func windowsHelperStateName(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start-pending"
	case svc.StopPending:
		return "stop-pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue-pending"
	case svc.PausePending:
		return "pause-pending"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("state-%d", state)
	}
}
