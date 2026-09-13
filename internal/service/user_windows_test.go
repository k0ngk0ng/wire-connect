//go:build windows && amd64

package service

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type windowsUserSequenceCommands struct {
	calls     []userRecordedCommand
	outputs   [][]byte
	runErrors []error
}

func (r *windowsUserSequenceCommands) Run(_ context.Context, name string, args ...string) error {
	r.calls = append(r.calls, userRecordedCommand{name: name, args: append([]string(nil), args...)})
	if len(r.runErrors) == 0 {
		return nil
	}
	err := r.runErrors[0]
	r.runErrors = r.runErrors[1:]
	return err
}

func (r *windowsUserSequenceCommands) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, userRecordedCommand{name: name, args: append([]string(nil), args...)})
	if len(r.outputs) == 0 {
		return nil, nil
	}
	out := r.outputs[0]
	r.outputs = r.outputs[1:]
	return out, nil
}

func TestWindowsUserTaskNameIsScopedToCurrentSID(t *testing.T) {
	oldSID := windowsUserSIDFn
	t.Cleanup(func() { windowsUserSIDFn = oldSID })
	windowsUserSIDFn = func() (string, error) { return "S-1-5-21-100-200-300-400", nil }
	got, err := windowsUserTaskName("office")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "wire-connect\\user-") || !strings.HasSuffix(got, "\\office") {
		t.Fatalf("task name = %q; want SID namespace and profile", got)
	}
	old := got
	windowsUserSIDFn = func() (string, error) { return "S-1-5-21-999-888-777-666", nil }
	other, err := windowsUserTaskName("office")
	if err != nil {
		t.Fatal(err)
	}
	if other == old {
		t.Fatalf("task name %q was not isolated from another SID", other)
	}
}

func TestWindowsUserTaskXMLIsInteractivePersistentAndShellSafe(t *testing.T) {
	data := string(windowsUserTaskXML(`C:\Users\test user\wire-connect\office\wirectl-connect.exe`, []string{
		"resume", "--name", "office", "--state-dir", `C:\Users\test user\state&bad`, "--foreground",
	}, "S-1-5-21-100-200-300-400"))
	for _, want := range []string{
		"<LogonTrigger>",
		"<UserId>S-1-5-21-100-200-300-400</UserId>",
		"<LogonType>InteractiveToken</LogonType>",
		"<RunLevel>LeastPrivilege</RunLevel>",
		"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
		"<RestartOnFailure><Interval>PT1M</Interval><Count>2147483647</Count></RestartOnFailure>",
		"resume --name office --state-dir",
		"&amp;",
	} {
		if !strings.Contains(data, want) {
			t.Fatalf("task XML lacks %q:\n%s", want, data)
		}
	}
	if strings.Contains(data, "schtasks") || strings.Contains(data, "cmd.exe") {
		t.Fatalf("task XML unexpectedly invokes a shell:\n%s", data)
	}
}

func TestWindowsUserTaskStateScriptEscapesTaskPathAndName(t *testing.T) {
	script := windowsUserTaskStateScript(`wire-connect\user-ab'cd\of'fice`)
	for _, want := range []string{
		"$s.GetFolder('\\wire-connect\\user-ab''cd')",
		"$f.GetTask('of''fice')",
		"GetBaseException().HResult",
		"-2147024894",
		"-2147024893",
		"$ProgressPreference='SilentlyContinue'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("state script lacks %q: %s", want, script)
		}
	}
}

func TestWindowsUserTaskExistsUsesDirectMockedCommand(t *testing.T) {
	oldCommands := userPlatformCommands
	oldPowerShell := windowsUserPowerShell
	t.Cleanup(func() { userPlatformCommands, windowsUserPowerShell = oldCommands, oldPowerShell })
	commands := &windowsUserSequenceCommands{outputs: [][]byte{[]byte(`3`)}}
	userPlatformCommands = commands
	windowsUserPowerShell = func() (string, error) { return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, nil }
	got, err := windowsUserTaskExists(context.Background(), `C:\Windows\System32\schtasks.exe`, `wire-connect\user-abcd\office`)
	if err != nil || !got {
		t.Fatalf("task exists = %t, %v; want true, nil", got, err)
	}
	if len(commands.calls) != 1 || commands.calls[0].name != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` || len(commands.calls[0].args) != 5 || commands.calls[0].args[3] != "-EncodedCommand" {
		t.Fatalf("Task Scheduler state query = %#v", commands.calls)
	}
}

func TestWindowsUserTaskExistsReturnsFalseForNumericNotFoundState(t *testing.T) {
	oldCommands := userPlatformCommands
	oldPowerShell := windowsUserPowerShell
	t.Cleanup(func() { userPlatformCommands, windowsUserPowerShell = oldCommands, oldPowerShell })
	commands := &windowsUserSequenceCommands{outputs: [][]byte{[]byte(`-1`)}}
	userPlatformCommands = commands
	windowsUserPowerShell = func() (string, error) { return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, nil }
	got, err := windowsUserTaskExists(context.Background(), `C:\Windows\System32\schtasks.exe`, `wire-connect\user-abcd\office`)
	if err != nil || got {
		t.Fatalf("task exists = %t, %v; want false, nil", got, err)
	}
}

func TestWindowsUserStopWaitsBeforeReplacingExecutable(t *testing.T) {
	oldCommands := userPlatformCommands
	oldPowerShell := windowsUserPowerShell
	t.Cleanup(func() { userPlatformCommands, windowsUserPowerShell = oldCommands, oldPowerShell })
	commands := &windowsUserSequenceCommands{outputs: [][]byte{
		[]byte(`4`),
		[]byte(`3`),
	}}
	userPlatformCommands = commands
	windowsUserPowerShell = func() (string, error) { return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, nil }
	if err := windowsUserStopTask(context.Background(), `C:\Windows\System32\schtasks.exe`, `wire-connect\user-abcd\office`, "office"); err != nil {
		t.Fatal(err)
	}
	if len(commands.calls) != 4 {
		t.Fatalf("stop calls = %#v; want End, Change, and two PowerShell state calls", commands.calls)
	}
	if commands.calls[0].args[0] != "/Change" || commands.calls[1].args[0] != "/End" || commands.calls[2].name != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` || commands.calls[3].name != commands.calls[2].name {
		t.Fatalf("stop call order = %#v", commands.calls)
	}
	for _, call := range commands.calls[2:] {
		if len(call.args) != 5 || call.args[3] != "-EncodedCommand" || call.args[4] == "" {
			t.Fatalf("PowerShell state call = %#v; want encoded command", call)
		}
	}
}

func TestWindowsUserStopIgnoresLocalizedEndErrorWhenNumericStateIsStopped(t *testing.T) {
	oldCommands := userPlatformCommands
	oldPowerShell := windowsUserPowerShell
	t.Cleanup(func() { userPlatformCommands, windowsUserPowerShell = oldCommands, oldPowerShell })
	commands := &windowsUserSequenceCommands{
		outputs:   [][]byte{[]byte(`3`)},
		runErrors: []error{nil, errors.New("Die Aufgabe wird nicht ausgeführt")},
	}
	userPlatformCommands = commands
	windowsUserPowerShell = func() (string, error) { return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, nil }
	if err := windowsUserStopTask(context.Background(), `C:\Windows\System32\schtasks.exe`, `wire-connect\user-abcd\office`, "office"); err != nil {
		t.Fatalf("localized not-running error = %v; want nil", err)
	}
	if len(commands.calls) != 3 || commands.calls[0].args[0] != "/Change" || commands.calls[1].args[0] != "/End" || commands.calls[2].args[3] != "-EncodedCommand" {
		t.Fatalf("stop calls = %#v; want disable, end, and numeric state query", commands.calls)
	}
}

func TestWindowsUserCheckUsesCurrentSIDAndTaskScheduler(t *testing.T) {
	oldCommands, oldSchtasks, oldSID := userPlatformCommands, windowsUserSchtasks, windowsUserSIDFn
	t.Cleanup(func() { userPlatformCommands, windowsUserSchtasks, windowsUserSIDFn = oldCommands, oldSchtasks, oldSID })
	commands := &userRecordingCommands{}
	userPlatformCommands = commands
	windowsUserSchtasks = func() (string, error) { return `C:\Windows\System32\schtasks.exe`, nil }
	windowsUserSIDFn = func() (string, error) { return "S-1-5-21-100-200-300-400", nil }
	if err := UserCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(commands.calls) != 1 || len(commands.calls[0].args) != 4 || commands.calls[0].args[0] != "/Query" || commands.calls[0].args[1] != "/FO" || commands.calls[0].args[2] != "CSV" || commands.calls[0].args[3] != "/NH" {
		t.Fatalf("schtasks check = %#v; want /Query /FO CSV /NH", commands.calls)
	}
}
