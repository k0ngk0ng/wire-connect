package service

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type userRecordingCommands struct {
	calls   []userRecordedCommand
	outputs map[string][]byte
}

type userRecordedCommand struct {
	name string
	args []string
}

func (r *userRecordingCommands) Run(_ context.Context, name string, args ...string) error {
	r.calls = append(r.calls, userRecordedCommand{name: name, args: append([]string(nil), args...)})
	return nil
}

func (r *userRecordingCommands) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, userRecordedCommand{name: name, args: append([]string(nil), args...)})
	if r.outputs == nil {
		return nil, nil
	}
	return append([]byte(nil), r.outputs[strings.Join(args, "\x00")]...), nil
}

func TestUserServiceArgsAreExplicitAndShellIndependent(t *testing.T) {
	state := `/Users/test user/state;$(touch p)`
	got, err := UserServiceArgs("office_1", state)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"resume", "--name", "office_1", "--state-dir", state, "--foreground"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UserServiceArgs = %#v; want %#v", got, want)
	}
	for _, arg := range got {
		if strings.ContainsRune(arg, 0) {
			t.Fatal("service argument contains NUL")
		}
	}
}

func TestUserServiceArgsRejectsUnsafeProfileNames(t *testing.T) {
	for _, name := range []string{"bad.name", "bad name", "../escape", "" + strings.Repeat("x", 65)} {
		if _, err := UserServiceArgs(name, "/tmp/state"); err == nil {
			t.Fatalf("UserServiceArgs accepted unsafe name %q", name)
		}
	}
}

func TestUserServiceAPIsCheckContextAndNameBeforePlatform(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := UserInstall(canceled, Config{Executable: "/tmp/wirectl-connect", StateDir: "/tmp/wire-connect-state"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("UserInstall canceled error = %v; want context.Canceled", err)
	}
	if err := UserStop(canceled, "default"); !errors.Is(err, context.Canceled) {
		t.Fatalf("UserStop canceled error = %v; want context.Canceled", err)
	}
	if _, err := UserStatus(canceled, "default"); !errors.Is(err, context.Canceled) {
		t.Fatalf("UserStatus canceled error = %v; want context.Canceled", err)
	}
	if err := UserUninstall(canceled, "default"); !errors.Is(err, context.Canceled) {
		t.Fatalf("UserUninstall canceled error = %v; want context.Canceled", err)
	}
	if err := UserCheck(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("UserCheck canceled error = %v; want context.Canceled", err)
	}
}
