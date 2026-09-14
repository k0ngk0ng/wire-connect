//go:build (linux && (amd64 || arm64)) || (darwin && (amd64 || arm64))

package service

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"testing"
)

func TestExecCommandRunnerDoesNotMapRawProcessKillToContext(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("shell unavailable: %v", err)
	}

	_, err = (execCommandRunner{}).Output(context.Background(), shell, "-c", "kill -KILL $$")
	if err == nil {
		t.Fatal("killed command unexpectedly succeeded")
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("raw process kill was classified as context cancellation: %v", err)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("command error = %v; want *exec.ExitError", err)
	}
	status, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("process status = %#v; want SIGKILL", exitErr.ProcessState.Sys())
	}
}
