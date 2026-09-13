//go:build windows && amd64

package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

var (
	windowsUserSchtasks     = findWindowsUserSchtasks
	windowsUserPowerShell   = findWindowsUserPowerShell
	windowsUserTaskExistsFn = windowsUserTaskExists
	windowsUserSIDFn        = windowsUserSIDString
)

func userInstall(ctx context.Context, cfg normalizedConfig) error {
	installed, err := windowsUserInstalledExecutable(cfg.Name)
	if err != nil {
		return err
	}
	manager, err := windowsUserSchtasks()
	if err != nil {
		return err
	}
	task, err := windowsUserTaskName(cfg.Name)
	if err != nil {
		return err
	}
	exists, err := windowsUserTaskExistsFn(ctx, manager, task)
	if err != nil {
		return err
	}
	if exists {
		if err := windowsUserStopTask(ctx, manager, task, cfg.Name); err != nil {
			return err
		}
	}
	if err := windowsUserCopyAtomic(ctx, cfg.Executable, installed); err != nil {
		return fmt.Errorf("wire-connect: install user executable: %w", err)
	}
	// wireguard-go loads the official Wintun DLL beside the executable on
	// Windows. Keep the user service self-contained just like the system
	// service installer.
	sourceWintun := filepathJoin(filepathDir(cfg.Executable), "wintun.dll")
	if err := validateUserSource(sourceWintun); err != nil {
		return fmt.Errorf("wire-connect: official wintun.dll is required beside executable: %w", err)
	}
	if err := windowsUserCopyAtomic(ctx, sourceWintun, filepathJoin(filepathDir(installed), "wintun.dll")); err != nil {
		return fmt.Errorf("wire-connect: install user wintun.dll: %w", err)
	}
	args, err := UserServiceArgs(cfg.Name, cfg.StateDir)
	if err != nil {
		return err
	}
	sid, err := windowsUserSIDFn()
	if err != nil {
		return err
	}
	xmlData := windowsUserTaskXML(installed, args, sid)
	xmlPath, err := windowsUserWriteTaskXML(ctx, filepathDir(installed), xmlData)
	if err != nil {
		return err
	}
	defer os.Remove(xmlPath)
	if err := runCommand(ctx, userPlatformCommands, manager, "/Create", "/TN", task, "/XML", xmlPath, "/F"); err != nil {
		return fmt.Errorf("wire-connect: create user scheduled task %q: %w", cfg.Name, err)
	}
	if err := runCommand(ctx, userPlatformCommands, manager, "/Run", "/TN", task); err != nil {
		return fmt.Errorf("wire-connect: start user scheduled task %q: %w", cfg.Name, err)
	}
	return nil
}

func userStop(ctx context.Context, name string) error { return windowsUserStop(ctx, name) }
func userUninstall(ctx context.Context, name string) error {
	return windowsUserUninstall(ctx, name)
}
func userStatus(ctx context.Context, name string) (string, error) {
	return windowsUserStatus(ctx, name)
}
func userCheck(ctx context.Context) error { return windowsUserCheck(ctx) }

func windowsUserStop(ctx context.Context, name string) error {
	manager, err := windowsUserSchtasks()
	if err != nil {
		return err
	}
	task, err := windowsUserTaskName(name)
	if err != nil {
		return err
	}
	exists, err := windowsUserTaskExistsFn(ctx, manager, task)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %q", ErrNotInstalled, name)
	}
	return windowsUserStopTask(ctx, manager, task, name)
}

func windowsUserStopTask(ctx context.Context, manager, task, name string) error {
	// Disable first so a logon trigger or a persisted KeepAlive policy cannot
	// start another instance while the current one is being ended.
	if err := runCommand(ctx, userPlatformCommands, manager, "/Change", "/TN", task, "/DISABLE"); err != nil {
		state, stateErr := windowsUserTaskNumericState(ctx, task)
		if stateErr != nil {
			return fmt.Errorf("wire-connect: disable user scheduled task %q: %w (state query: %v)", name, err, stateErr)
		}
		if state != windowsUserTaskNotFound {
			return fmt.Errorf("wire-connect: disable user scheduled task %q: %w", name, err)
		}
		return nil
	}

	endErr := runCommand(ctx, userPlatformCommands, manager, "/End", "/TN", task)
	if endErr != nil {
		// schtasks localizes its error text. Re-read the Task Scheduler enum so a
		// harmless "not running" result is recognized independently of UI locale.
		state, stateErr := windowsUserTaskNumericState(ctx, task)
		if stateErr != nil {
			return fmt.Errorf("wire-connect: stop user scheduled task %q: %w (state query: %v)", name, endErr, stateErr)
		}
		if state == windowsUserTaskNotFound || windowsUserTaskStopped(state) {
			return nil
		}
		return fmt.Errorf("wire-connect: stop user scheduled task %q: %w", name, endErr)
	}
	if err := windowsUserWaitTaskStopped(ctx, manager, task, name); err != nil {
		return err
	}
	return nil
}

func windowsUserWaitTaskStopped(ctx context.Context, manager, task, name string) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := contextErr(ctx); err != nil {
			return err
		}
		state, err := windowsUserTaskNumericState(ctx, task)
		if err != nil {
			return fmt.Errorf("wire-connect: query user scheduled task %q state while stopping: %w", name, err)
		}
		if state == windowsUserTaskNotFound || windowsUserTaskStopped(state) {
			return nil
		}
		if state == 0 {
			return errors.New("wire-connect: scheduled task returned an unknown state while stopping")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wire-connect: timed out waiting for user scheduled task %q to stop", name)
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

func windowsUserUninstall(ctx context.Context, name string) error {
	manager, err := windowsUserSchtasks()
	if err != nil {
		return err
	}
	task, err := windowsUserTaskName(name)
	if err != nil {
		return err
	}
	exists, err := windowsUserTaskExistsFn(ctx, manager, task)
	if err != nil {
		return err
	}
	if exists {
		if err := windowsUserStopTask(ctx, manager, task, name); err != nil {
			return err
		}
		if err := runCommand(ctx, userPlatformCommands, manager, "/Delete", "/TN", task, "/F"); err != nil {
			state, stateErr := windowsUserTaskNumericState(ctx, task)
			if stateErr != nil {
				return fmt.Errorf("wire-connect: remove user scheduled task %q: %w (state query: %v)", name, err, stateErr)
			}
			if state != windowsUserTaskNotFound {
				return fmt.Errorf("wire-connect: remove user scheduled task %q: %w", name, err)
			}
		}
	}
	installed, err := windowsUserInstalledDir(name)
	if err != nil {
		return err
	}
	if err := windowsUserRemoveDir(installed); err != nil {
		return fmt.Errorf("wire-connect: remove user executable: %w", err)
	}
	return nil
}

func windowsUserStatus(ctx context.Context, name string) (string, error) {
	task, err := windowsUserTaskName(name)
	if err != nil {
		return "", err
	}
	state, err := windowsUserTaskNumericState(ctx, task)
	if err != nil {
		return "", fmt.Errorf("wire-connect: query user scheduled task state %q: %w", name, err)
	}
	if state == windowsUserTaskNotFound {
		return "", fmt.Errorf("%w: %q", ErrNotInstalled, name)
	}
	switch state {
	case 1, 3:
		return "stopped", nil
	case 2:
		return "queued", nil
	case 4:
		return "running", nil
	default:
		return "unknown", nil
	}
}

func windowsUserCheck(ctx context.Context) error {
	if _, err := windowsUserSIDFn(); err != nil {
		return err
	}
	manager, err := windowsUserSchtasks()
	if err != nil {
		return err
	}
	if err := runCommand(ctx, userPlatformCommands, manager, "/Query", "/FO", "CSV", "/NH"); err != nil {
		return fmt.Errorf("wire-connect: Windows Task Scheduler is unavailable: %w", err)
	}
	return nil
}

func windowsUserTaskName(name string) (string, error) {
	sid, err := windowsUserSIDFn()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(sid))
	// The task namespace is machine-wide even when a task runs as a normal
	// user. Include a stable SID-derived namespace so two users can install the
	// same profile name without seeing or replacing one another's task.
	return fmt.Sprintf("wire-connect\\user-%x\\%s", digest[:8], name), nil
}

const windowsUserTaskNotFound = -1

func windowsUserTaskExists(ctx context.Context, _ string, task string) (bool, error) {
	state, err := windowsUserTaskNumericState(ctx, task)
	if err != nil {
		return false, err
	}
	return state != windowsUserTaskNotFound, nil
}

func windowsUserTaskStopped(state int) bool {
	return state == 1 || state == 3 // TASK_STATE_DISABLED or TASK_STATE_READY
}

// windowsUserTaskNumericState asks Task Scheduler for its enum value rather
// than parsing the localized text emitted by schtasks. PowerShell receives an
// encoded command, so neither a profile name nor a task path is re-parsed by a
// shell while status and stop waiters inspect the task.
func windowsUserTaskNumericState(ctx context.Context, task string) (int, error) {
	powershell, err := windowsUserPowerShell()
	if err != nil {
		return 0, err
	}
	script := windowsUserTaskStateScript(task)
	encoded := base64UTF16(script)
	out, err := commandOutput(ctx, userPlatformCommands, powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	if err != nil {
		return 0, err
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || value < windowsUserTaskNotFound || value > 4 {
		if err == nil {
			err = fmt.Errorf("invalid Task Scheduler state %q", strings.TrimSpace(string(out)))
		}
		return 0, err
	}
	return value, nil
}

func windowsUserTaskStateScript(task string) string {
	separator := strings.LastIndexByte(task, '\\')
	path, name := `\`, task
	if separator >= 0 {
		// ITaskFolder::GetFolder accepts the root path as "\\", but rejects a
		// non-root folder path with a trailing separator (0x8007007B).
		path += strings.TrimSuffix(task[:separator+1], `\`)
		name = task[separator+1:]
	}
	// Task names are normalized before reaching this function. Keep the
	// explicit quote escaping as a second invariant if this helper is reused.
	path = strings.ReplaceAll(path, `'`, `''`)
	name = strings.ReplaceAll(name, `'`, `''`)
	return "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';try{$s=New-Object -ComObject 'Schedule.Service';$s.Connect();$f=$s.GetFolder('" + path + "');$t=$f.GetTask('" + name + "');[Console]::Out.Write([int]$t.State)}catch{$h=$_.Exception.GetBaseException().HResult;if($h -eq -2147024894 -or $h -eq -2147024893){[Console]::Out.Write('-1')}else{throw}}"
}

func base64UTF16(value string) string {
	encoded := utf16.Encode([]rune(value))
	data := make([]byte, len(encoded)*2)
	for i, r := range encoded {
		data[i*2] = byte(r)
		data[i*2+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func windowsUserSIDString() (string, error) {
	token := windows.GetCurrentProcessToken()
	userInfo, err := token.GetTokenUser()
	if err != nil || userInfo == nil || userInfo.User.Sid == nil {
		if err == nil {
			err = errors.New("token has no user SID")
		}
		return "", fmt.Errorf("wire-connect: get current Windows user SID: %w", err)
	}
	return userInfo.User.Sid.String(), nil
}

func windowsUserTaskXML(executable string, args []string, sid string) []byte {
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n")
	b.WriteString("<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\" version=\"1.4\">\r\n")
	b.WriteString("  <RegistrationInfo><Author>")
	windowsUserXMLEscape(&b, sid)
	b.WriteString("</Author></RegistrationInfo>\r\n")
	b.WriteString("  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>")
	windowsUserXMLEscape(&b, sid)
	b.WriteString("</UserId></LogonTrigger></Triggers>\r\n")
	b.WriteString("  <Principals><Principal id=\"Author\"><UserId>")
	windowsUserXMLEscape(&b, sid)
	b.WriteString("</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\r\n")
	b.WriteString("  <Settings>\r\n")
	b.WriteString("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n")
	b.WriteString("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n")
	b.WriteString("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n")
	b.WriteString("    <AllowHardTerminate>true</AllowHardTerminate>\r\n")
	b.WriteString("    <StartWhenAvailable>true</StartWhenAvailable>\r\n")
	b.WriteString("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n")
	b.WriteString("    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\r\n")
	b.WriteString("    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n")
	b.WriteString("    <Enabled>true</Enabled>\r\n")
	b.WriteString("    <Hidden>false</Hidden>\r\n")
	b.WriteString("    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n")
	b.WriteString("    <WakeToRun>false</WakeToRun>\r\n")
	b.WriteString("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n")
	b.WriteString("    <RestartOnFailure><Interval>PT1M</Interval><Count>255</Count></RestartOnFailure>\r\n")
	b.WriteString("    <Priority>7</Priority>\r\n")
	b.WriteString("  </Settings>\r\n")
	b.WriteString("  <Actions Context=\"Author\"><Exec><Command>")
	windowsUserXMLEscape(&b, executable)
	b.WriteString("</Command><Arguments>")
	var arguments strings.Builder
	for i, arg := range args {
		if i > 0 {
			arguments.WriteByte(' ')
		}
		arguments.WriteString(syscall.EscapeArg(arg))
	}
	windowsUserXMLEscape(&b, arguments.String())
	b.WriteString("</Arguments><WorkingDirectory>")
	windowsUserXMLEscape(&b, filepathDir(executable))
	b.WriteString("</WorkingDirectory></Exec></Actions>\r\n")
	b.WriteString("</Task>\r\n")
	return windowsUserUTF16LEBOM(b.Bytes())
}

func windowsUserUTF16LEBOM(utf8XML []byte) []byte {
	encoded := utf16.Encode([]rune(string(utf8XML)))
	data := make([]byte, 2+len(encoded)*2)
	data[0], data[1] = 0xff, 0xfe
	for i, r := range encoded {
		data[2+i*2] = byte(r)
		data[2+i*2+1] = byte(r >> 8)
	}
	return data
}

func windowsUserXMLEscape(b *bytes.Buffer, value string) {
	for _, r := range value {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
}

func findWindowsUserSchtasks() (string, error) {
	if windir := userGetenv("WINDIR"); windir != "" {
		candidate := filepathJoin(windir, "System32", "schtasks.exe")
		st, err := os.Stat(candidate)
		if err == nil && st.Mode().IsRegular() {
			return candidate, nil
		}
	}
	path, err := exec.LookPath("schtasks.exe")
	if err != nil {
		return "", errors.New("wire-connect: schtasks.exe was not found")
	}
	return path, nil
}

func findWindowsUserPowerShell() (string, error) {
	if windir := userGetenv("WINDIR"); windir != "" {
		candidate := filepathJoin(windir, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		st, err := os.Stat(candidate)
		if err == nil && st.Mode().IsRegular() {
			return candidate, nil
		}
	}
	path, err := exec.LookPath("powershell.exe")
	if err != nil {
		return "", errors.New("wire-connect: powershell.exe was not found")
	}
	return path, nil
}

// Small wrappers keep the Windows build's path operations easy to replace in
// tests without shadowing filepath's package name in command assertions.
var filepathJoin = func(elem ...string) string { return filepath.Join(elem...) }
var filepathDir = filepath.Dir
