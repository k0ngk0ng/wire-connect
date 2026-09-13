package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"time"

	"tailscale.com/net/stun"
)

// ProbeSTUN tests the configured server's UDP reachability and reports the
// mapping it observes. A single STUN endpoint cannot classify every NAT type.
func (c *Client) ProbeSTUN(ctx context.Context) (netip.AddrPort, time.Duration, error) {
	u, err := url.Parse(c.Server)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(u.Hostname(), "3478"))
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	tx := stun.NewTxID()
	request := stun.Request(tx)
	buf := make([]byte, 1500)
	for range 3 {
		start := time.Now()
		conn.SetDeadline(start.Add(time.Second))
		if _, err := conn.Write(request); err != nil {
			return netip.AddrPort{}, 0, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return netip.AddrPort{}, 0, ctx.Err()
			}
			continue
		}
		got, addr, err := stun.ParseResponse(buf[:n])
		if err != nil || got != tx {
			continue
		}
		return addr, time.Since(start), nil
	}
	return netip.AddrPort{}, 0, fmt.Errorf("no STUN response from %s:3478; check UDP egress and the server's UDP listener/firewall", u.Hostname())
}
