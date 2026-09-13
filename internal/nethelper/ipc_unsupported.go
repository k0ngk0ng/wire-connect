//go:build !linux && !darwin && !windows

package nethelper

import (
	"context"
	"errors"
	"net"
)

func dial(context.Context) (net.Conn, error)            { return nil, ErrUnavailable }
func listen(string) (net.Listener, func() error, error) { return nil, nil, ErrUnavailable }
func authenticate(net.Conn, string) error               { return errors.New("unsupported platform") }
func networkLock(context.Context) (func(), error)       { return nil, ErrUnavailable }
