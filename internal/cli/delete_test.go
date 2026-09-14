package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/service"
)

func TestForgetConnectionStopsBeforeRemovingOnlySelectedPair(t *testing.T) {
	s := config.Store{Dir: filepath.Join(t.TempDir(), "state")}
	for _, name := range []string{"profile-office", "profile-default", "credentials"} {
		if err := s.Write(name, map[string]string{"preserve": "value"}); err != nil {
			t.Fatal(err)
		}
	}
	var calls []string
	ops := connectionLifecycle{
		stop: func(_ context.Context, dir, name string) error {
			if dir != s.Dir || name != "office" {
				t.Fatalf("wrong target %s %s", dir, name)
			}
			calls = append(calls, "stop")
			return nil
		},
		service: func(_ context.Context, name string, uninstall bool) error {
			if name != "office" || !uninstall {
				t.Fatal("must uninstall only office")
			}
			calls = append(calls, "uninstall")
			return nil
		},
		status: func(_ context.Context, dir, name string, _ any) error {
			var saved any
			if err := s.Read("profile-office", &saved); err != nil {
				t.Fatal("removed profile before process exit", err)
			}
			calls = append(calls, "status")
			return os.ErrNotExist
		},
	}
	removed, err := forgetConnection(context.Background(), s, "office", ops)
	if err != nil || !removed {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	if !reflect.DeepEqual(calls, []string{"stop", "uninstall", "status"}) {
		t.Fatal(calls)
	}
	var saved any
	if err := s.Read("profile-office", &saved); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, name := range []string{"profile-default", "credentials"} {
		if err := s.Read(name, &saved); err != nil {
			t.Fatal("removed unrelated state", err)
		}
	}
	calls = nil
	if removed, err := forgetConnection(context.Background(), s, "office", ops); err != nil || removed {
		t.Fatalf("second delete: %v %v", removed, err)
	}
	if len(calls) != 0 {
		t.Fatal("missing profile must not touch services", calls)
	}
}

func TestForgetConnectionRetainsPairOnLifecycleFailure(t *testing.T) {
	for _, failure := range []string{"service", "ipc", "cancelled"} {
		t.Run(failure, func(t *testing.T) {
			s := config.Store{Dir: filepath.Join(t.TempDir(), "state")}
			if err := s.Write("profile-office", config.Profile{PairID: "keep"}); err != nil {
				t.Fatal(err)
			}
			failureErr := errors.New("permission denied")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops := connectionLifecycle{
				stop: func(context.Context, string, string) error { return nil },
				service: func(context.Context, string, bool) error {
					if failure == "service" {
						return failureErr
					}
					return service.ErrNotInstalled
				},
				status: func(context.Context, string, string, any) error {
					if failure == "cancelled" {
						cancel()
						return nil
					}
					return failureErr
				},
			}
			removed, err := forgetConnection(ctx, s, "office", ops)
			if removed || err == nil {
				t.Fatalf("removed=%v err=%v", removed, err)
			}
			var p config.Profile
			if err := s.Read("profile-office", &p); err != nil || p.PairID != "keep" {
				t.Fatal("lost saved pair", err)
			}
		})
	}
}

func TestStopAlreadyStoppedConnection(t *testing.T) {
	ops := connectionLifecycle{
		stop:    func(context.Context, string, string) error { return os.ErrNotExist },
		service: func(context.Context, string, bool) error { return service.ErrNotInstalled },
		status:  func(context.Context, string, string, any) error { return os.ErrNotExist },
	}
	if err := ops.stopAndWait(context.Background(), config.Store{}, "default", false); err != nil {
		t.Fatal(err)
	}
}

func TestStopWaitsForEndpointToClose(t *testing.T) {
	checks := 0
	ops := connectionLifecycle{
		stop:    func(context.Context, string, string) error { return nil },
		service: func(context.Context, string, bool) error { return service.ErrNotInstalled },
		status: func(context.Context, string, string, any) error {
			checks++
			switch checks {
			case 1:
				return nil
			case 2:
				return io.EOF
			default:
				return os.ErrNotExist
			}
		},
	}
	if err := ops.stopAndWait(context.Background(), config.Store{}, "default", false); err != nil {
		t.Fatal(err)
	}
	if checks != 3 {
		t.Fatalf("checks=%d", checks)
	}
}

func TestConnectionManagementCommandRouting(t *testing.T) {
	for _, command := range []string{"delete", "remove", "list"} {
		t.Run(command, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			var out bytes.Buffer
			err := Run(context.Background(), []string{command, "--state-dir", dir}, "test", strings.NewReader(""), &out, &out)
			if err != nil {
				t.Fatal(err)
			}
			want := "No saved connection named default."
			if command == "list" {
				want = "No saved connections"
			}
			if !strings.Contains(out.String(), want) {
				t.Fatal(out.String())
			}
		})
	}
	var out bytes.Buffer
	err := Run(context.Background(), []string{"delete", "office"}, "test", strings.NewReader(""), &out, &out)
	if err == nil || !strings.Contains(err.Error(), "--name NAME") {
		t.Fatalf("positional delete: %v", err)
	}
}

func TestStopUsesSeparateStageBudgets(t *testing.T) {
	checkBudget := func(ctx context.Context, want time.Duration) {
		t.Helper()
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > want || time.Until(deadline) < want-time.Second {
			t.Fatalf("stage deadline = %v; expected budget %s", deadline, want)
		}
	}
	var ipcContext, serviceContext context.Context
	ops := connectionLifecycle{
		stop: func(ctx context.Context, _, _ string) error {
			checkBudget(ctx, 3*time.Second)
			ipcContext = ctx
			return nil
		},
		service: func(ctx context.Context, _ string, _ bool) error {
			if ipcContext.Err() != context.Canceled {
				t.Fatal("IPC context not released")
			}
			checkBudget(ctx, 90*time.Second)
			serviceContext = ctx
			return nil
		},
		status: func(ctx context.Context, _, _ string, _ any) error {
			if serviceContext.Err() != context.Canceled {
				t.Fatal("service context not released")
			}
			checkBudget(ctx, 15*time.Second)
			return os.ErrNotExist
		},
	}
	if err := ops.stopAndWait(context.Background(), config.Store{}, "office", true); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteServiceFailureExplainsTimeoutAndAllowsRetry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		timeout bool
	}{
		{"timeout", errors.Join(errors.New("signal: killed"), context.DeadlineExceeded), true},
		{"killed", errors.New("signal: killed"), false},
		{"canceled", context.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := config.Store{Dir: filepath.Join(t.TempDir(), "state")}
			if err := s.Write("profile-office", config.Profile{PairID: "keep"}); err != nil {
				t.Fatal(err)
			}
			failure := tc.failure
			ops := connectionLifecycle{
				stop:    func(context.Context, string, string) error { return os.ErrNotExist },
				service: func(context.Context, string, bool) error { return failure },
				status:  func(context.Context, string, string, any) error { return os.ErrNotExist },
			}
			removed, err := forgetConnection(context.Background(), s, "office", ops)
			if removed || !errors.Is(err, tc.failure) || !strings.Contains(err.Error(), "saved pair retained") {
				t.Fatalf("removed=%v err=%v", removed, err)
			}
			if strings.Contains(err.Error(), "timed out") != tc.timeout {
				t.Fatalf("incorrect timeout classification: %v", err)
			}
			if tc.timeout && !strings.Contains(err.Error(), "retry wirectl connect delete --name office") {
				t.Fatalf("missing retry guidance: %v", err)
			}
			var saved config.Profile
			if err := s.Read("profile-office", &saved); err != nil || saved.PairID != "keep" {
				t.Fatalf("saved pair lost: %v", err)
			}
			failure = service.ErrNotInstalled
			if removed, err := forgetConnection(context.Background(), s, "office", ops); !removed || err != nil {
				t.Fatalf("retry removed=%v err=%v", removed, err)
			}
		})
	}
}

func TestStopServiceRespectsParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ops := connectionLifecycle{
		stop: func(context.Context, string, string) error { return nil },
		service: func(stage context.Context, _ string, _ bool) error {
			cancel()
			<-stage.Done()
			return errors.New("signal: killed")
		},
		status: func(context.Context, string, string, any) error {
			t.Fatal("must not check endpoint after cancellation")
			return nil
		},
	}
	if err := ops.stopAndWait(ctx, config.Store{}, "office", false); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost parent cancellation: %v", err)
	}
}
