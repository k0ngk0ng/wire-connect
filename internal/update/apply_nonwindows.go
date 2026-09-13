//go:build !windows

package update

import (
	"context"
	"errors"
	"io"
)

// Apply is the Windows-only handoff entry point.  Keep a platform-neutral
// stub so callers can share hidden command dispatch without build-tagged CLI
// code; executing it on Unix is always an error.
func Apply(ctx context.Context, _ []string, _ io.Writer) error {
	if ctx == nil {
		return errors.New("wire-connect: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupportedPlatform
}

// Cleanup is the Windows-only handoff cleanup entry point.  Keep a stub so
// shared hidden command dispatch compiles on Unix targets.
func Cleanup(ctx context.Context, _ []string, _ io.Writer) error {
	if ctx == nil {
		return errors.New("wire-connect: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupportedPlatform
}
