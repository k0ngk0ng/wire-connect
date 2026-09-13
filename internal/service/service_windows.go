//go:build windows && amd64

package service

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

const windowsServiceWait = 30 * time.Second

type windowsServiceManager interface {
	Disconnect() error
	OpenService(string) (windowsServiceHandle, error)
	CreateService(string, string, mgr.Config, ...string) (windowsServiceHandle, error)
}

type windowsServiceHandle interface {
	Close() error
	Delete() error
	Start(...string) error
	Control(svc.Cmd) (svc.Status, error)
	Query() (svc.Status, error)
	Config() (mgr.Config, error)
	UpdateConfig(mgr.Config) error
	SetRecoveryActions([]mgr.RecoveryAction, uint32) error
	SetRecoveryActionsOnNonCrashFailures(bool) error
}

type nativeWindowsManager struct{ manager *mgr.Mgr }

func (m nativeWindowsManager) Disconnect() error {
	if m.manager == nil {
		return nil
	}
	return m.manager.Disconnect()
}

func (m nativeWindowsManager) OpenService(name string) (windowsServiceHandle, error) {
	s, err := m.manager.OpenService(name)
	if err != nil {
		return nil, err
	}
	return nativeWindowsService{service: s}, nil
}

func (m nativeWindowsManager) CreateService(name, executable string, cfg mgr.Config, args ...string) (windowsServiceHandle, error) {
	s, err := m.manager.CreateService(name, executable, cfg, args...)
	if err != nil {
		return nil, err
	}
	return nativeWindowsService{service: s}, nil
}

type nativeWindowsService struct{ service *mgr.Service }

func (s nativeWindowsService) Close() error               { return s.service.Close() }
func (s nativeWindowsService) Delete() error              { return s.service.Delete() }
func (s nativeWindowsService) Start(args ...string) error { return s.service.Start(args...) }
func (s nativeWindowsService) Control(cmd svc.Cmd) (svc.Status, error) {
	return s.service.Control(cmd)
}
func (s nativeWindowsService) Query() (svc.Status, error)  { return s.service.Query() }
func (s nativeWindowsService) Config() (mgr.Config, error) { return s.service.Config() }
func (s nativeWindowsService) UpdateConfig(cfg mgr.Config) error {
	return s.service.UpdateConfig(cfg)
}
func (s nativeWindowsService) SetRecoveryActions(actions []mgr.RecoveryAction, reset uint32) error {
	return s.service.SetRecoveryActions(actions, reset)
}
func (s nativeWindowsService) SetRecoveryActionsOnNonCrashFailures(enabled bool) error {
	return s.service.SetRecoveryActionsOnNonCrashFailures(enabled)
}

var (
	windowsConnectManager = connectWindowsManager
	windowsRequireAdmin   = requireWindowsAdmin
	windowsSetServiceACL  = setWindowsServiceACL
)

func connectWindowsManager() (windowsServiceManager, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("wire-connect: connect to Windows Service Control Manager: %w", err)
	}
	return nativeWindowsManager{manager: m}, nil
}

func windowsNativeName(name string) string {
	return "wire-connect-" + name
}

func windowsServiceArgs(cfg normalizedConfig) []string {
	return serviceArgs(cfg)
}

func windowsBinaryPath(executable string, args []string) string {
	commandLine := syscall.EscapeArg(executable)
	for _, arg := range args {
		commandLine += " " + syscall.EscapeArg(arg)
	}
	return commandLine
}

// Install installs a LocalSystem Windows service using the native SCM API.
// Both the executable and the official adjacent Wintun DLL are copied into a
// protected Program Files directory before the service is started.
func Install(ctx context.Context, cfg Config) error {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := windowsRequireAdmin(); err != nil {
		return err
	}
	if platformFiles == nil {
		return errors.New("wire-connect: nil platform file operator")
	}
	if err := platformFiles.ValidateStateDir(ctx, normalized.StateDir); err != nil {
		return err
	}
	executable, err := windowsInstalledExecutable(normalized.Name)
	if err != nil {
		return err
	}
	wintun, err := windowsInstalledWintun(normalized.Name)
	if err != nil {
		return err
	}
	sourceWintun := filepath.Join(filepath.Dir(normalized.Executable), "wintun.dll")
	if err := windowsValidateSource(normalized.Executable); err != nil {
		return err
	}
	if err := windowsValidateSource(sourceWintun); err != nil {
		return fmt.Errorf("wire-connect: official wintun.dll is required beside executable: %w", err)
	}

	manager, err := windowsConnectManager()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	serviceName := windowsNativeName(normalized.Name)
	serviceArgs := windowsServiceArgs(normalized)
	service, err := manager.OpenService(serviceName)
	created := false
	if err != nil {
		if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return fmt.Errorf("wire-connect: open Windows service %q: %w", normalized.Name, err)
		}
	} else {
		// Stop before replacing the image.  Windows keeps an executable image
		// alive while its process runs, so updating the file alone would leave
		// an old connection process serving the profile.
		if err := stopAndDisableWindows(ctx, service, normalized.Name); err != nil {
			service.Close()
			return err
		}
	}
	// Wintun is loaded from the installed executable's directory.  Requiring
	// and copying the adjacent release DLL prevents a service from loading a
	// same-named DLL from the current working directory.
	if err := platformFiles.CopyProtected(ctx, normalized.Executable, executable); err != nil {
		if service != nil {
			service.Close()
		}
		return fmt.Errorf("wire-connect: install executable: %w", err)
	}
	if err := platformFiles.CopyProtected(ctx, sourceWintun, wintun); err != nil {
		if service != nil {
			service.Close()
		}
		return fmt.Errorf("wire-connect: install official wintun.dll beside executable: %w", err)
	}
	if service == nil {
		service, err = manager.CreateService(serviceName, executable, windowsServiceConfig(normalized), serviceArgs...)
		if err != nil {
			return fmt.Errorf("wire-connect: create Windows service %q: %w", normalized.Name, err)
		}
		created = true
	}
	defer service.Close()
	if !created {
		serviceConfig, err := service.Config()
		if err != nil {
			return fmt.Errorf("wire-connect: read Windows service %q configuration: %w", normalized.Name, err)
		}
		serviceConfig.ServiceType = windows.SERVICE_WIN32_OWN_PROCESS
		serviceConfig.StartType = mgr.StartAutomatic
		serviceConfig.ErrorControl = mgr.ErrorNormal
		serviceConfig.BinaryPathName = windowsBinaryPath(executable, serviceArgs)
		serviceConfig.DisplayName = windowsServiceConfig(normalized).DisplayName
		serviceConfig.Description = windowsServiceConfig(normalized).Description
		serviceConfig.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
		serviceConfig.DelayedAutoStart = false
		if err := service.UpdateConfig(serviceConfig); err != nil {
			return fmt.Errorf("wire-connect: update Windows service %q configuration: %w", normalized.Name, err)
		}
	}
	if err := service.SetRecoveryActions(windowsRecoveryActions(), 24*60*60); err != nil {
		return fmt.Errorf("wire-connect: configure Windows service %q recovery: %w", normalized.Name, err)
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("wire-connect: configure Windows service %q failure recovery: %w", normalized.Name, err)
	}
	if err := windowsSetServiceACL(serviceName); err != nil {
		return fmt.Errorf("wire-connect: protect Windows service %q permissions: %w", normalized.Name, err)
	}
	if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("wire-connect: start Windows service %q: %w", normalized.Name, err)
	}
	if err := waitWindowsState(ctx, service, svc.Running, windowsServiceWait); err != nil {
		return fmt.Errorf("wire-connect: wait for Windows service %q to start: %w", normalized.Name, err)
	}
	return nil
}

func windowsServiceConfig(cfg normalizedConfig) mgr.Config {
	return mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "wire-connect (" + cfg.Name + ")",
		Description:  "wire-connect persistent tunnel (" + cfg.Name + ")",
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
}

func windowsRecoveryActions() []mgr.RecoveryAction {
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
}

// Stop requests a graceful stop, waits for SERVICE_STOPPED, and changes the
// SCM start type to disabled.  Credentials and package files are retained.
func Stop(ctx context.Context, name string) error {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := windowsRequireAdmin(); err != nil {
		return err
	}
	manager, err := windowsConnectManager()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(windowsNativeName(normalizedName))
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return fmt.Errorf("%w: %q", ErrNotInstalled, normalizedName)
		}
		return fmt.Errorf("wire-connect: open Windows service %q: %w", normalizedName, err)
	}
	defer service.Close()
	if err := stopAndDisableWindows(ctx, service, normalizedName); err != nil {
		return err
	}
	return nil
}

func stopAndDisableWindows(ctx context.Context, service windowsServiceHandle, name string) error {
	current, err := service.Query()
	if err != nil {
		return fmt.Errorf("wire-connect: query Windows service %q: %w", name, err)
	}
	if current.State != svc.Stopped {
		if _, err := service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return fmt.Errorf("wire-connect: stop Windows service %q: %w", name, err)
		}
		if err := waitWindowsState(ctx, service, svc.Stopped, windowsServiceWait); err != nil {
			return fmt.Errorf("wire-connect: wait for Windows service %q to stop: %w", name, err)
		}
	}
	config, err := service.Config()
	if err != nil {
		return fmt.Errorf("wire-connect: read Windows service %q configuration: %w", name, err)
	}
	config.StartType = mgr.StartDisabled
	if err := service.UpdateConfig(config); err != nil {
		return fmt.Errorf("wire-connect: disable Windows service %q: %w", name, err)
	}
	return nil
}

// Uninstall removes the SCM record and the package-owned Program Files copy.
// The configured state directory is intentionally outside this operation.
func Uninstall(ctx context.Context, name string) error {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := windowsRequireAdmin(); err != nil {
		return err
	}
	manager, err := windowsConnectManager()
	if err != nil {
		return err
	}
	serviceName := windowsNativeName(normalizedName)
	service, openErr := manager.OpenService(serviceName)
	if openErr == nil {
		if err := stopAndDisableWindows(ctx, service, normalizedName); err != nil {
			service.Close()
			manager.Disconnect()
			return err
		}
		if err := service.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			service.Close()
			manager.Disconnect()
			return fmt.Errorf("wire-connect: delete Windows service %q: %w", normalizedName, err)
		}
		service.Close()
		if err := waitWindowsDeletion(ctx, manager, serviceName, windowsServiceWait); err != nil {
			manager.Disconnect()
			return fmt.Errorf("wire-connect: wait for Windows service %q removal: %w", normalizedName, err)
		}
	} else if !errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		manager.Disconnect()
		return fmt.Errorf("wire-connect: open Windows service %q for uninstall: %w", normalizedName, openErr)
	}
	manager.Disconnect()
	if platformFiles == nil {
		return errors.New("wire-connect: nil platform file operator")
	}
	dir, err := windowsInstalledDir(normalizedName)
	if err != nil {
		return err
	}
	if err := platformFiles.RemoveDir(ctx, dir); err != nil {
		return fmt.Errorf("wire-connect: remove installed executable directory: %w", err)
	}
	return nil
}

func waitWindowsDeletion(ctx context.Context, manager windowsServiceManager, name string, timeout time.Duration) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		h, err := manager.OpenService(name)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		if err == nil {
			// A handle can be opened while DeleteService is completing.  Close it
			// before trying again so deletion is not held up by this poller.
			// The interface intentionally makes close errors non-fatal here.
			h.Close()
		} else if !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("timed out waiting for service deletion")
		case <-ticker.C:
		}
	}
}

func waitWindowsState(ctx context.Context, service windowsServiceHandle, desired svc.State, timeout time.Duration) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == desired {
			return nil
		}
		if desired == svc.Running && status.State == svc.Stopped {
			return errors.New("service stopped before reaching running state")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("timed out waiting for state %s", windowsStateName(desired))
		case <-ticker.C:
		}
	}
}

// Status returns a compact name for the native SCM state.
func Status(ctx context.Context, name string) (string, error) {
	normalizedName, err := normalizeName(name)
	if err != nil {
		return "", err
	}
	if err := contextErr(ctx); err != nil {
		return "", err
	}
	manager, err := windowsConnectManager()
	if err != nil {
		return "", err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(windowsNativeName(normalizedName))
	if err != nil {
		return "", fmt.Errorf("wire-connect: open Windows service %q: %w", normalizedName, err)
	}
	defer service.Close()
	state, err := service.Query()
	if err != nil {
		return "", fmt.Errorf("wire-connect: query Windows service %q: %w", normalizedName, err)
	}
	return windowsStateName(state.State), nil
}

func windowsStateName(state svc.State) string {
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

func requireWindowsAdmin() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("wire-connect: inspect Windows elevation: %w", err)
	}
	defer token.Close()
	if !token.IsElevated() {
		return errors.New("wire-connect: service installation requires an elevated Administrator process")
	}
	return nil
}

func setWindowsServiceACL(name string) error {
	// LocalSystem and built-in Administrators can administer the service; no
	// interactive user receives SERVICE_CHANGE_CONFIG or SERVICE_START rights.
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
