// Command wire-connect-user-service-testutil is used only by the opt-in
// current-user service-manager lifecycle test. It exercises the same
// foreground invocation that a user service records, but it does not open a
// TUN device or contact a network peer.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/localctl"
)

type lifecycleStatus struct {
	Name     string `json:"name"`
	StateDir string `json:"state_dir"`
	PairID   string `json:"pair_id"`
	PID      int    `json:"pid"`
}

type lifecycleReceipt struct {
	Event    string `json:"event"`
	Name     string `json:"name"`
	StateDir string `json:"state_dir"`
	PairID   string `json:"pair_id"`
	PID      int    `json:"pid"`
}

func main() {
	ctx, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignal()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	stateDir, name, err := parseUserServiceArgs(os.Args[1:])
	if err != nil {
		return err
	}
	store := config.Store{Dir: stateDir}
	var profile config.Profile
	if err := store.Read("profile-"+name, &profile); err != nil {
		return fmt.Errorf("read integration profile: %w", err)
	}
	if err := store.Write("service-receipt-"+name, lifecycleReceipt{
		Event: "started", Name: name, StateDir: stateDir, PairID: profile.PairID, PID: os.Getpid(),
	}); err != nil {
		return fmt.Errorf("write integration startup receipt: %w", err)
	}
	status := lifecycleStatus{Name: name, StateDir: stateDir, PairID: profile.PairID, PID: os.Getpid()}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			_ = store.Write("service-stop-"+name, lifecycleReceipt{
				Event: "local-stop", Name: name, StateDir: stateDir, PairID: profile.PairID, PID: os.Getpid(),
			})
			cancel()
		})
	}
	control, err := localctl.Listen(runCtx, stateDir, name, func() any { return status }, stop)
	if err != nil {
		return fmt.Errorf("listen integration control endpoint: %w", err)
	}
	defer control.Close()
	<-runCtx.Done()
	return nil
}

func parseUserServiceArgs(args []string) (stateDir, name string, err error) {
	if len(args) != 6 || args[0] != "resume" || args[1] != "--name" || args[3] != "--state-dir" || args[5] != "--foreground" {
		return "", "", errors.New("usage: wire-connect-user-service-testutil resume --name NAME --state-dir DIR --foreground")
	}
	if strings.TrimSpace(args[2]) == "" || strings.TrimSpace(args[4]) == "" {
		return "", "", errors.New("service state directory and name are required")
	}
	return args[4], args[2], nil
}
