//go:build !(linux && (amd64 || arm64)) && !(darwin && arm64) && !(windows && amd64)

package netsetup

import (
	"context"
	"io"
	"os"
)

func currentIdentity() (string, error)             { return "", ErrUnsupported }
func normalizeIdentity(string) (string, error)     { return "", ErrUnsupported }
func validateExecutablePlatform(os.FileInfo) error { return ErrUnsupported }
func elevated() bool                               { return false }
func requestElevation(context.Context, string, string, io.Reader, io.Writer, io.Writer) error {
	return ErrUnsupported
}
func installPlatform(context.Context, normalizedConfig) error { return ErrUnsupported }
func stopPlatform(context.Context, string) error              { return ErrUnsupported }
func uninstallPlatform(context.Context, string) error         { return ErrUnsupported }
func statusPlatform(context.Context, string) (string, error)  { return "", ErrUnsupported }
