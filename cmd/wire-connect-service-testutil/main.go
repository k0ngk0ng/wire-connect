// Command wire-connect-service-testutil is an intentionally small executable
// used by the opt-in service-manager lifecycle test. It exercises the same
// service.Run entry point as the released client, but does not open a TUN
// device or contact a network peer.
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
	"github.com/k0ngk0ng/wire-connect/internal/service"
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
	handled, err := service.Run(run)
	if handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	stateDir, name, err := parseServiceArgs(os.Args[1:])
	if err != nil {
		return err
	}
	store := config.Store{Dir: stateDir}
	var profile config.Profile
	if err := store.Read("profile-"+name, &profile); err != nil {
		return fmt.Errorf("read integration profile: %w", err)
	}

	receipt := lifecycleReceipt{
		Event:    "started",
		Name:     name,
		StateDir: stateDir,
		PairID:   profile.PairID,
		PID:      os.Getpid(),
	}
	if err := store.Write("service-receipt-"+name, receipt); err != nil {
		return fmt.Errorf("write integration startup receipt: %w", err)
	}
	status := lifecycleStatus{
		Name:     name,
		StateDir: stateDir,
		PairID:   profile.PairID,
		PID:      os.Getpid(),
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			// The receipt is written before cancellation so the integration test
			// can prove that a localctl request reached this service account.
			_ = store.Write("service-stop-"+name, lifecycleReceipt{
				Event:    "local-stop",
				Name:     name,
				StateDir: stateDir,
				PairID:   profile.PairID,
				PID:      os.Getpid(),
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

func parseServiceArgs(args []string) (stateDir, name string, err error) {
	// serviceArgs emits this exact shape. Keeping the test helper strict makes
	// a malformed service-manager command line fail early instead of silently
	// selecting another profile.
	if len(args) != 6 || args[0] != "resume" || args[1] != "--state-dir" || args[3] != "--name" || args[5] != "--service" {
		return "", "", errors.New("usage: wire-connect-service-testutil resume --state-dir DIR --name NAME --service")
	}
	if strings.TrimSpace(args[2]) == "" || strings.TrimSpace(args[4]) == "" {
		return "", "", errors.New("service state directory and name are required")
	}
	return args[2], args[4], nil
}
