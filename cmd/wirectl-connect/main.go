package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/k0ngk0ng/wire-connect/internal/cli"
	"github.com/k0ngk0ng/wire-connect/internal/service"
)

var version = "dev"

func main() {
	run := func(ctx context.Context) error {
		return cli.Run(ctx, os.Args[1:], version, os.Stdin, os.Stdout, os.Stderr)
	}
	if handled, err := service.Run(run); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
}
