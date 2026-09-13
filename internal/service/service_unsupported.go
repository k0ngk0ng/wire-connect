//go:build !(linux && (amd64 || arm64)) && !(darwin && (amd64 || arm64)) && !(windows && amd64)

package service

import "context"

func Install(context.Context, Config) error { return ErrUnsupported }
func Stop(context.Context, string) error    { return ErrUnsupported }
func Uninstall(context.Context, string) error {
	return ErrUnsupported
}
func Status(context.Context, string) (string, error) { return "", ErrUnsupported }
func Run(func(context.Context) error) (bool, error)  { return false, ErrUnsupported }
