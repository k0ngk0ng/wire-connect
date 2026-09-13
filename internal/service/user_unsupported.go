//go:build !(linux && (amd64 || arm64)) && !(darwin && (amd64 || arm64)) && !(windows && amd64)

package service

import "context"

func userInstall(context.Context, normalizedConfig) error { return ErrUnsupported }
func userStop(context.Context, string) error              { return ErrUnsupported }
func userUninstall(context.Context, string) error         { return ErrUnsupported }
func userStatus(context.Context, string) (string, error)  { return "", ErrUnsupported }
func userCheck(context.Context) error                     { return ErrUnsupported }
