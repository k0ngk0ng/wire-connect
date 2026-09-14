package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/client"
	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/localctl"
	"github.com/k0ngk0ng/wire-connect/internal/service"
)

// Keep lifecycle operations injectable so tests never operate on the user's
// real services. The production path always uses the same native manager as
// connect/resume and the same authenticated local control endpoint as stop.
type connectionLifecycle struct {
	stop    func(context.Context, string, string) error
	service func(context.Context, string, bool) error
	status  func(context.Context, string, string, any) error
}

func nativeConnectionLifecycle() connectionLifecycle {
	return connectionLifecycle{stop: localctl.Stop, service: stopClient, status: localctl.Status}
}

func (ops connectionLifecycle) stopAndWait(ctx context.Context, s config.Store, name string, uninstall bool) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Disable the restart policy even if the process exits between requests.
	ipcCtx, ipcCancel := context.WithTimeout(ctx, 3*time.Second)
	ipcErr := ops.stop(ipcCtx, s.Dir, name)
	ipcCancel()
	serviceErr := ops.service(ctx, name, uninstall)
	if serviceErr != nil && !errors.Is(serviceErr, service.ErrNotInstalled) {
		return fmt.Errorf("stop service for %s: %w", name, serviceErr)
	}
	// A successful native service stop can resolve an unresponsive IPC endpoint.
	// Always check the final state before removing a saved pair.
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("waiting for connection %s to stop: %w", name, err)
		}
		var st client.Status
		err := ops.status(ctx, s.Dir, name, &st)
		if localctl.IsNotRunning(err) {
			return nil
		}
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.ECONNRESET) {
			return fmt.Errorf("cannot confirm connection %s has stopped: %w", name, errors.Join(err, ipcErr))
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for connection %s to stop: %w", name, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (a app) deleteConnection(ctx context.Context, args []string) error {
	f, c, err := a.flags("delete")
	if err != nil {
		return err
	}
	f.Usage = func() {
		fmt.Fprintln(a.errOut, "Usage: wirectl connect delete [--name NAME] [--state-dir PATH]\nStop a connection, remove its service and forget its saved pair.\nThe name defaults to default. Reconnecting requires a new pairing.\nOther connections, server login and the other device's profile are retained.")
	}
	if err := parse(f, args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("delete takes no positional arguments; use --name NAME")
	}
	s, err := c.store()
	if err != nil {
		return err
	}
	removed, err := forgetConnection(ctx, s, c.name, nativeConnectionLifecycle())
	if err != nil {
		return err
	}
	if !removed {
		fmt.Fprintf(a.out, "No saved connection named %s.\n", c.name)
		return nil
	}
	fmt.Fprintf(a.out, "Deleted connection %s. Its service and saved pair have been removed.\nPair again with wirectl connect <server> [code] to reconnect.\n", c.name)
	return nil
}

func forgetConnection(ctx context.Context, s config.Store, name string, ops connectionLifecycle) (bool, error) {
	if !profileName.MatchString(name) {
		return false, errors.New("invalid connection name")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// Validate the saved file before any service mutation. It may contain
	// older fields, so deletion does not require parsing a usable Profile.
	var saved any
	if err := s.Read("profile-"+name, &saved); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := ops.stopAndWait(ctx, s, name, true); err != nil {
		return false, fmt.Errorf("saved pair retained: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("saved pair retained: %w", err)
	}
	if err := s.Remove("profile-" + name); err != nil {
		return false, err
	}
	return true, nil
}
