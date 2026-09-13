//go:build windows && amd64

package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type fakeWindowsService struct {
	queries   []svc.Status
	config    mgr.Config
	control   svc.Cmd
	updated   mgr.Config
	queryNext int
}

func (f *fakeWindowsService) Close() error          { return nil }
func (f *fakeWindowsService) Delete() error         { return nil }
func (f *fakeWindowsService) Start(...string) error { return nil }
func (f *fakeWindowsService) Control(cmd svc.Cmd) (svc.Status, error) {
	f.control = cmd
	return svc.Status{State: svc.StopPending}, nil
}
func (f *fakeWindowsService) Query() (svc.Status, error) {
	if len(f.queries) == 0 {
		return svc.Status{}, nil
	}
	i := f.queryNext
	if i >= len(f.queries) {
		i = len(f.queries) - 1
	}
	f.queryNext++
	return f.queries[i], nil
}
func (f *fakeWindowsService) Config() (mgr.Config, error) { return f.config, nil }
func (f *fakeWindowsService) UpdateConfig(cfg mgr.Config) error {
	f.updated = cfg
	return nil
}
func (f *fakeWindowsService) SetRecoveryActions([]mgr.RecoveryAction, uint32) error { return nil }
func (f *fakeWindowsService) SetRecoveryActionsOnNonCrashFailures(bool) error       { return nil }

func TestWindowsServiceNameRequiresExplicitPairingProfile(t *testing.T) {
	got, err := windowsServiceName([]string{"wirectl-connect.exe", "resume", "--state-dir", `C:\ProgramData\wire-connect`, "--name", "office", "--service"})
	if err != nil || got != "office" {
		t.Fatalf("windowsServiceName = %q, %v; want office, nil", got, err)
	}
	if _, err := windowsServiceName([]string{"wirectl-connect.exe", "resume", "--service"}); err == nil {
		t.Fatal("windowsServiceName accepted invocation without --name")
	}
	if _, err := windowsServiceName([]string{"wirectl-connect.exe", "resume", "--name", "bad.name", "--service"}); err == nil {
		t.Fatal("windowsServiceName accepted invalid service name")
	}
}

func TestWindowsBinaryPathUsesWindowsArgumentEscaping(t *testing.T) {
	got := windowsBinaryPath(`C:\Program Files\wire-connect\office\wirectl-connect.exe`, []string{"resume", "--state-dir", `C:\ProgramData\wire connect\office`, "--name", "office", "--service"})
	for _, value := range []string{`C:\Program Files\wire-connect\office\wirectl-connect.exe`, "resume", `C:\ProgramData\wire connect\office`, "office", "--service"} {
		if !strings.Contains(got, value) {
			t.Fatalf("binary path %q does not contain escaped argument %q", got, value)
		}
	}
	if strings.Contains(got, "&") {
		t.Fatalf("binary path contains an unescaped command operator: %q", got)
	}
}

func TestWindowsRecoveryActionsAreRestartOnly(t *testing.T) {
	actions := windowsRecoveryActions()
	if len(actions) != 3 {
		t.Fatalf("recovery actions = %#v; want three", actions)
	}
	for _, action := range actions {
		if action.Type != mgr.ServiceRestart || action.Delay <= 0 {
			t.Fatalf("invalid recovery action %#v", action)
		}
	}
}

func TestWindowsStateName(t *testing.T) {
	for _, tt := range []struct {
		state svc.State
		want  string
	}{
		{svc.Stopped, "stopped"},
		{svc.Running, "running"},
		{svc.StartPending, "start-pending"},
		{svc.StopPending, "stop-pending"},
	} {
		if got := windowsStateName(tt.state); got != tt.want {
			t.Fatalf("windowsStateName(%v) = %q; want %q", tt.state, got, tt.want)
		}
	}
	if got := windowsStateName(svc.State(999)); got != "state-999" {
		t.Fatalf("unknown state = %q", got)
	}
}

func TestStopAndDisableWindowsWaitsForProcessExit(t *testing.T) {
	oldOpen, oldWait, oldClose := windowsOpenProcess, windowsWaitForSingleObject, windowsCloseProcess
	t.Cleanup(func() {
		windowsOpenProcess, windowsWaitForSingleObject, windowsCloseProcess = oldOpen, oldWait, oldClose
	})
	var openedPID uint32
	var waitedHandle windows.Handle
	var waitedMillis uint32
	var closedHandle windows.Handle
	windowsOpenProcess = func(pid uint32) (windows.Handle, error) {
		openedPID = pid
		return windows.Handle(7), nil
	}
	windowsWaitForSingleObject = func(handle windows.Handle, millis uint32) (uint32, error) {
		waitedHandle = handle
		waitedMillis = millis
		return windows.WAIT_OBJECT_0, nil
	}
	windowsCloseProcess = func(handle windows.Handle) error {
		closedHandle = handle
		return nil
	}

	service := &fakeWindowsService{
		queries: []svc.Status{
			{State: svc.Running, ProcessId: 42},
			{State: svc.Stopped},
		},
		config: mgr.Config{StartType: mgr.StartAutomatic},
	}
	if err := stopAndDisableWindows(context.Background(), service, "office"); err != nil {
		t.Fatal(err)
	}
	if service.control != svc.Stop {
		t.Fatalf("control command = %v; want stop", service.control)
	}
	if openedPID != 42 {
		t.Fatalf("opened process PID = %d; want 42", openedPID)
	}
	if waitedHandle != windows.Handle(7) || waitedMillis == 0 || waitedMillis > uint32(windowsProcessWaitSlice/time.Millisecond) {
		t.Fatalf("process wait = handle %v, %dms; want handle 7 and bounded wait", waitedHandle, waitedMillis)
	}
	if closedHandle != windows.Handle(7) {
		t.Fatalf("closed process handle = %v; want 7", closedHandle)
	}
	if service.updated.StartType != mgr.StartDisabled {
		t.Fatalf("updated service start type = %v; want disabled", service.updated.StartType)
	}
}

func TestStopAndDisableWindowsAllowsPendingServiceWithoutPID(t *testing.T) {
	oldOpen := windowsOpenProcess
	t.Cleanup(func() { windowsOpenProcess = oldOpen })
	opened := false
	windowsOpenProcess = func(uint32) (windows.Handle, error) {
		opened = true
		return windows.Handle(7), nil
	}
	service := &fakeWindowsService{
		queries: []svc.Status{
			{State: svc.StartPending},
			{State: svc.Stopped},
		},
		config: mgr.Config{StartType: mgr.StartAutomatic},
	}
	if err := stopAndDisableWindows(context.Background(), service, "office"); err != nil {
		t.Fatal(err)
	}
	if opened {
		t.Fatal("opened a process for a service status without a PID")
	}
	if service.control != svc.Stop || service.updated.StartType != mgr.StartDisabled {
		t.Fatalf("service stop/update = control %v, start type %v; want stop and disabled", service.control, service.updated.StartType)
	}
}

func TestStopAndDisableWindowsRequeriesVanishedPID(t *testing.T) {
	oldOpen := windowsOpenProcess
	t.Cleanup(func() { windowsOpenProcess = oldOpen })
	var opened []uint32
	windowsOpenProcess = func(pid uint32) (windows.Handle, error) {
		opened = append(opened, pid)
		return windows.InvalidHandle, windows.ERROR_INVALID_PARAMETER
	}
	service := &fakeWindowsService{
		queries: []svc.Status{
			{State: svc.Running, ProcessId: 42},
			{State: svc.Stopped},
		},
		config: mgr.Config{StartType: mgr.StartAutomatic},
	}
	if err := stopAndDisableWindows(context.Background(), service, "office"); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 || opened[0] != 42 {
		t.Fatalf("opened PIDs = %v; want only vanished PID 42", opened)
	}
	if service.control != 0 || service.updated.StartType != mgr.StartDisabled {
		t.Fatalf("service stop/update = control %v, start type %v; want no second stop and disabled", service.control, service.updated.StartType)
	}
}

func TestStopAndDisableWindowsDoesNotReopenVanishedPID(t *testing.T) {
	oldOpen, oldWait, oldClose := windowsOpenProcess, windowsWaitForSingleObject, windowsCloseProcess
	t.Cleanup(func() {
		windowsOpenProcess, windowsWaitForSingleObject, windowsCloseProcess = oldOpen, oldWait, oldClose
	})
	var opened []uint32
	windowsOpenProcess = func(pid uint32) (windows.Handle, error) {
		opened = append(opened, pid)
		return windows.InvalidHandle, windows.ERROR_INVALID_PARAMETER
	}
	windowsWaitForSingleObject = func(windows.Handle, uint32) (uint32, error) {
		return windows.WAIT_OBJECT_0, nil
	}
	windowsCloseProcess = func(windows.Handle) error { return nil }
	service := &fakeWindowsService{
		queries: []svc.Status{
			{State: svc.Running, ProcessId: 42},
			{State: svc.Running, ProcessId: 42},
			{State: svc.Stopped},
		},
		config: mgr.Config{StartType: mgr.StartAutomatic},
	}
	if err := stopAndDisableWindows(context.Background(), service, "office"); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 || opened[0] != 42 {
		t.Fatalf("opened PIDs = %v; want one attempt for vanished PID 42", opened)
	}
	if service.control != svc.Stop || service.updated.StartType != mgr.StartDisabled {
		t.Fatalf("service stop/update = control %v, start type %v; want stop and disabled", service.control, service.updated.StartType)
	}
}
