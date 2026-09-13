//go:build windows && amd64

package service

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
)

var (
	windowsIsService   = svc.IsWindowsService
	windowsServiceRun  = svc.Run
	windowsCommandLine = func() []string { return append([]string(nil), os.Args...) }
)

// Run enters the Windows service dispatcher when the process was started by
// SCM.  When called from a console it returns (false, nil), allowing the
// caller to run its ordinary CLI.  Stop and Shutdown cancel the context and
// wait for fn to finish all cleanup before reporting SERVICE_STOPPED.
func Run(fn func(context.Context) error) (handled bool, err error) {
	if fn == nil {
		return false, errors.New("wire-connect: nil service function")
	}
	inService, err := windowsIsService()
	if err != nil {
		return false, fmt.Errorf("wire-connect: detect Windows service context: %w", err)
	}
	if !inService {
		return false, nil
	}
	name, err := windowsServiceName(windowsCommandLine())
	if err != nil {
		return true, err
	}
	err = windowsServiceRun(windowsNativeName(name), windowsHandler{fn: fn})
	if err != nil {
		return true, fmt.Errorf("wire-connect: Windows service %q: %w", name, err)
	}
	return true, nil
}

func windowsServiceName(args []string) (string, error) {
	for i := 1; i+1 < len(args); i++ {
		if args[i] != "--name" {
			continue
		}
		name, err := normalizeName(args[i+1])
		if err != nil {
			return "", err
		}
		return name, nil
	}
	return "", errors.New("wire-connect: Windows service invocation is missing --name")
}

type windowsHandler struct {
	fn func(context.Context) error
}

func (h windowsHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- h.fn(ctx)
	}()

	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status := svc.Status{State: svc.StartPending, Accepts: accepted, WaitHint: 30_000}
	changes <- status
	status = svc.Status{State: svc.Running, Accepts: accepted}
	changes <- status

	for {
		select {
		case err := <-done:
			if err == nil {
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
			changes <- svc.Status{State: svc.Stopped}
			return true, serviceExitCode(err)
		case request, ok := <-requests:
			if !ok {
				cancel()
				err := <-done
				changes <- svc.Status{State: svc.Stopped}
				if err == nil || errors.Is(err, context.Canceled) {
					return false, 0
				}
				return true, serviceExitCode(err)
			}
			switch request.Cmd {
			case svc.Interrogate:
				changes <- status
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending, WaitHint: 30_000}
				cancel()
				err := <-done
				changes <- svc.Status{State: svc.Stopped}
				if err == nil || errors.Is(err, context.Canceled) {
					return false, 0
				}
				return true, serviceExitCode(err)
			}
		}
	}
}

func serviceExitCode(err error) uint32 {
	if err == nil {
		return 0
	}
	// Keep the SCM status useful without exposing arbitrary error strings as
	// an operating-system exit code.  A non-zero service-specific status is
	// enough for the event log and recovery policy to mark the run failed.
	if n, ok := err.(interface{ Unwrap() error }); ok && n.Unwrap() != nil {
		return serviceExitCode(n.Unwrap())
	}
	return 1
}
