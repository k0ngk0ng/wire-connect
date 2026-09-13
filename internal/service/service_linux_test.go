//go:build linux && (amd64 || arm64)

package service

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type recordingFiles struct {
	validations []string
	copies      [][2]string
	writes      []recordedWrite
	removedFile []string
	removedDir  []string
}

type recordedWrite struct {
	path string
	data []byte
	mode os.FileMode
}

func (f *recordingFiles) ValidateStateDir(_ context.Context, path string) error {
	f.validations = append(f.validations, path)
	return nil
}
func (f *recordingFiles) CopyProtected(_ context.Context, source, destination string) error {
	f.copies = append(f.copies, [2]string{source, destination})
	return nil
}
func (f *recordingFiles) WriteProtected(_ context.Context, path string, data []byte, mode os.FileMode) error {
	f.writes = append(f.writes, recordedWrite{path: path, data: append([]byte(nil), data...), mode: mode})
	return nil
}
func (f *recordingFiles) RemoveFile(_ context.Context, path string) error {
	f.removedFile = append(f.removedFile, path)
	return nil
}
func (f *recordingFiles) RemoveDir(_ context.Context, path string) error {
	f.removedDir = append(f.removedDir, path)
	return nil
}

type recordingCommands struct {
	calls   []recordedCommand
	outputs map[string][]byte
}

type recordedCommand struct {
	name string
	args []string
}

func (r *recordingCommands) Run(_ context.Context, name string, args ...string) error {
	r.calls = append(r.calls, recordedCommand{name: name, args: append([]string(nil), args...)})
	return nil
}
func (r *recordingCommands) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, recordedCommand{name: name, args: append([]string(nil), args...)})
	if r.outputs != nil {
		return append([]byte(nil), r.outputs[strings.Join(args, "\x00")]...), nil
	}
	return nil, nil
}

func TestLinuxInstallUsesProtectedCopyAndDirectSystemctlArguments(t *testing.T) {
	oldFiles, oldCommands, oldRoot, oldSystemctl := platformFiles, platformCommands, linuxRequireRoot, linuxSystemctl
	defer func() {
		platformFiles, platformCommands, linuxRequireRoot, linuxSystemctl = oldFiles, oldCommands, oldRoot, oldSystemctl
	}()
	files := &recordingFiles{}
	commands := &recordingCommands{}
	platformFiles = files
	platformCommands = commands
	linuxRequireRoot = func() error { return nil }
	linuxSystemctl = func() (string, error) { return "/test/systemctl", nil }

	state, err := filepath.Abs(filepath.Join(".cache", "service-test-state"))
	if err != nil {
		t.Fatal(err)
	}
	executable, err := filepath.Abs(filepath.Join(".cache", "wirectl-connect"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Install(context.Background(), Config{Executable: executable, StateDir: state, Name: "office"}); err != nil {
		t.Fatal(err)
	}
	if len(files.validations) != 1 || files.validations[0] != state {
		t.Fatalf("state validation = %#v; want %q", files.validations, state)
	}
	if len(files.copies) != 1 || files.copies[0] != [2]string{executable, "/usr/local/libexec/wire-connect/office/wirectl-connect"} {
		t.Fatalf("protected copy = %#v", files.copies)
	}
	if len(files.writes) != 1 {
		t.Fatalf("writes = %#v; want one systemd unit", files.writes)
	}
	unit := string(files.writes[0].data)
	if files.writes[0].path != "/etc/systemd/system/wire-connect-office.service" || files.writes[0].mode != 0644 {
		t.Fatalf("unit write = %#v", files.writes[0])
	}
	for _, want := range []string{
		`ExecStart="/usr/local/libexec/wire-connect/office/wirectl-connect" "resume" "--state-dir" "` + state + `" "--name" "office" "--service"`,
		"CapabilityBoundingSet=CAP_NET_ADMIN",
		"AmbientCapabilities=CAP_NET_ADMIN",
		"Restart=on-failure",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit lacks %q:\n%s", want, unit)
		}
	}
	if len(commands.calls) != 3 {
		t.Fatalf("commands = %#v; want daemon-reload, enable, and restart", commands.calls)
	}
	if !reflect.DeepEqual(commands.calls[0], recordedCommand{name: "/test/systemctl", args: []string{"daemon-reload"}}) || !reflect.DeepEqual(commands.calls[1], recordedCommand{name: "/test/systemctl", args: []string{"enable", "wire-connect-office.service"}}) || !reflect.DeepEqual(commands.calls[2], recordedCommand{name: "/test/systemctl", args: []string{"restart", "wire-connect-office.service"}}) {
		t.Fatalf("commands = %#v", commands.calls)
	}
}

func TestSystemdQuoteEscapesUnitSyntax(t *testing.T) {
	got := systemdQuote("a b\"c\\d\n$HOME/%i")
	want := `"a b\"c\\d\n$$HOME/%%i"`
	if got != want {
		t.Fatalf("systemdQuote = %q; want %q", got, want)
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("systemdQuote emitted a literal line break: %q", got)
	}
}

func TestLinuxStopAndUninstallPreserveState(t *testing.T) {
	oldFiles, oldCommands, oldRoot, oldSystemctl, oldUnitExists := platformFiles, platformCommands, linuxRequireRoot, linuxSystemctl, linuxUnitExists
	defer func() {
		platformFiles, platformCommands, linuxRequireRoot, linuxSystemctl, linuxUnitExists = oldFiles, oldCommands, oldRoot, oldSystemctl, oldUnitExists
	}()
	files := &recordingFiles{}
	commands := &recordingCommands{}
	platformFiles = files
	platformCommands = commands
	linuxRequireRoot = func() error { return nil }
	linuxSystemctl = func() (string, error) { return "/test/systemctl", nil }
	linuxUnitExists = func(string) (bool, error) { return true, nil }

	if err := Stop(context.Background(), "office"); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(context.Background(), "office"); err != nil {
		t.Fatal(err)
	}
	if len(files.removedFile) != 1 || files.removedFile[0] != "/etc/systemd/system/wire-connect-office.service" {
		t.Fatalf("removed service records = %#v", files.removedFile)
	}
	if len(files.removedDir) != 1 || files.removedDir[0] != "/usr/local/libexec/wire-connect/office" {
		t.Fatalf("removed directories = %#v", files.removedDir)
	}
	for _, path := range files.removedFile {
		if strings.Contains(path, "state") || strings.Contains(path, "credential") {
			t.Fatalf("uninstall touched user state path %q", path)
		}
	}
}

func TestStatusReturnsSystemdStateEvenForInactiveExit(t *testing.T) {
	oldCommands, oldSystemctl := platformCommands, linuxSystemctl
	defer func() { platformCommands, linuxSystemctl = oldCommands, oldSystemctl }()
	commands := &recordingCommands{outputs: map[string][]byte{"is-active\x00wire-connect-office.service": []byte("inactive\n")}}
	platformCommands = commands
	linuxSystemctl = func() (string, error) { return "/test/systemctl", nil }
	got, err := Status(context.Background(), "office")
	if err != nil || got != "inactive" {
		t.Fatalf("Status = %q, %v; want inactive, nil", got, err)
	}
}

func TestLinuxUnitRejectsNoUnexpectedShellOperator(t *testing.T) {
	cfg, err := normalizeConfig(Config{Executable: "/tmp/bin", StateDir: "/var/lib/wire-connect/x;touch", Name: "default"})
	if err != nil {
		t.Fatal(err)
	}
	unit := string(linuxUnit(cfg))
	if !strings.Contains(unit, `"/var/lib/wire-connect/x;touch"`) {
		t.Fatalf("unit did not preserve quoted state path:\n%s", unit)
	}
	if strings.Contains(unit, "ExecStart=/bin/sh") {
		t.Fatal("unit unexpectedly uses a shell")
	}
}

func TestRunCommandRejectsNilRunner(t *testing.T) {
	if err := runCommand(context.Background(), nil, "systemctl"); err == nil {
		t.Fatal("runCommand with nil runner succeeded")
	}
	if _, err := commandOutput(context.Background(), nil, "systemctl"); err == nil {
		t.Fatal("commandOutput with nil runner succeeded")
	}
}

var _ fileOperator = (*recordingFiles)(nil)
var _ commandRunner = (*recordingCommands)(nil)
