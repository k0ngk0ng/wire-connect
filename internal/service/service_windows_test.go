//go:build windows && amd64

package service

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

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
