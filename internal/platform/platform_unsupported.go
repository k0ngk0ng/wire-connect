//go:build !((linux && (amd64 || arm64)) || (darwin && (amd64 || arm64)) || (windows && amd64))

package platform

import (
	"context"
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

func validatePlatformName(string) error {
	return nil
}

func openPlatform(context.Context, Config) (tun.Device, func() error, error) {
	return nil, nil, fmt.Errorf("%w: client supports linux/darwin amd64 or arm64 and windows amd64", ErrUnsupported)
}

func checkPlatform(context.Context) error {
	return fmt.Errorf("%w: client supports linux/darwin amd64 or arm64 and windows amd64", ErrUnsupported)
}

func availablePlatform(context.Context, []netip.Addr) error {
	return fmt.Errorf("%w: client supports linux/darwin amd64 or arm64 and windows amd64", ErrUnsupported)
}
