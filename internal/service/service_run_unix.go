//go:build (linux && (amd64 || arm64)) || (darwin && (amd64 || arm64))

package service

import "context"

// Run is a no-op on Unix.  Unix service managers start the ordinary command
// line directly, so the caller continues into its normal CLI dispatcher.
func Run(func(context.Context) error) (handled bool, err error) {
	return false, nil
}
