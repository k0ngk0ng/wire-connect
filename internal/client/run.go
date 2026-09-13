package client

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/control"
	"github.com/k0ngk0ng/wire-connect/internal/platform"
	"github.com/k0ngk0ng/wire-connect/internal/transport"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"tailscale.com/types/key"
)

type RunOptions struct {
	Interface string
	MTU       int
	STUNURL   string
	RelayOnly bool
	Log       *slog.Logger
	OnStatus  func(Status)
	// TUN allows integration tests to attach an in-memory packet interface.
	// CLI callers leave it nil so platform.Open owns network setup/rollback.
	TUN tun.Device
}

type Status struct {
	Running       bool      `json:"running"`
	Mode          string    `json:"mode"`
	LocalIP       string    `json:"local_ip"`
	PeerIP        string    `json:"peer_ip"`
	Sent          uint64    `json:"sent"`
	Received      uint64    `json:"received"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	Updated       time.Time `json:"updated"`
}

func (c *Client) Run(ctx context.Context, p config.Profile, opts RunOptions) error {
	if err := validateProfile(p); err != nil {
		return err
	}
	if p.Server != c.Server {
		return errors.New("profile server does not match credential origin")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	var private key.NodePrivate
	var peer key.NodePublic
	if err := private.UnmarshalText([]byte(p.RelayPrivate)); err != nil {
		return errors.New("invalid saved relay identity")
	}
	if err := peer.UnmarshalText([]byte("nodekey:" + p.PeerRelayPublic)); err != nil {
		return errors.New("invalid peer relay identity")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	register := func() error {
		return c.request(ctx, "POST", "/v1/relay/register", control.RelayRegisterRequest{Key: private.Public().UntypedHexString()}, nil)
	}
	if err := register(); err != nil {
		var api *APIError
		if errors.As(err, &api) && (api.Status == 401 || api.Status == 403) {
			return err
		}
		opts.Log.Warn("server unavailable; reconnecting", "error", err)
	}
	bind, err := transport.New(ctx, transport.RelayConfig{URL: c.Server, Private: private, Peer: peer, HTTPClient: c.HTTP, Log: opts.Log})
	if err != nil {
		return err
	}
	defer bind.Shutdown()
	var td tun.Device
	var cleanup func() error
	if opts.TUN != nil {
		td = opts.TUN
		cleanup = td.Close
	} else {
		name := opts.Interface
		if name == "" {
			name = "wire0"
			if runtime.GOOS == "darwin" {
				name = "utun"
			}
		}
		local, _ := netip.ParseAddr(p.LocalIP)
		remote, _ := netip.ParseAddr(p.PeerIP)
		if err := platform.Available(ctx, local, remote); err != nil {
			return err
		}
		td, cleanup, err = platform.Open(ctx, platform.Config{Name: name, Local: local, Peer: remote, MTU: opts.MTU})
		if err != nil {
			return err
		}
	}
	wglog := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(format string, args ...any) { opts.Log.Debug(fmt.Sprintf(format, args...)) }}
	wg := device.NewDevice(td, bind, wglog)
	defer func() {
		if err := cleanup(); err != nil {
			opts.Log.Warn("tunnel cleanup", "error", err)
		}
		wg.Close()
	}()
	psk, err := hkdf.Key(sha256.New, p.Secret, nil, "wire-connect/wireguard-psk/v1", 32)
	if err != nil {
		return err
	}
	defer clear(psk)
	ipc := fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\npreshared_key=%s\nallowed_ip=%s/32\nendpoint=127.0.0.1:1\npersistent_keepalive_interval=25\n", hex.EncodeToString(p.WirePrivate), p.PeerWirePublic, hex.EncodeToString(psk), p.PeerIP)
	if err := wg.IpcSet(ipc); err != nil {
		return fmt.Errorf("configure WireGuard: %w", err)
	}
	if err := wg.Up(); err != nil {
		return fmt.Errorf("start WireGuard: %w", err)
	}
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	workers.Go(func() {
		nextRenewal := time.Now().Add(5 * time.Minute)
		for {
			if !pause(ctx, 5*time.Second) {
				return
			}
			if time.Now().Before(nextRenewal) && bind.Stats().RelayConnected {
				continue
			}
			if err := register(); err != nil {
				opts.Log.Debug("relay lease renewal failed", "error", err)
			} else {
				nextRenewal = time.Now().Add(5 * time.Minute)
			}
		}
	})
	workers.Go(func() { c.maintainDirect(ctx, p, bind, opts) })
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	update := func(running bool) {
		if opts.OnStatus == nil {
			return
		}
		stats := bind.Stats()
		st := Status{Running: running, Mode: stats.Mode, LocalIP: p.LocalIP, PeerIP: p.PeerIP, Sent: stats.Sent, Received: stats.Received, Updated: time.Now().UTC()}
		if ipc, err := wg.IpcGet(); err == nil {
			for line := range strings.SplitSeq(ipc, "\n") {
				if raw, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
					if sec, err := strconv.ParseInt(raw, 10, 64); err == nil && sec > 0 {
						st.LastHandshake = time.Unix(sec, 0).UTC()
					}
				}
			}
		}
		opts.OnStatus(st)
	}
	update(true)
	defer update(false)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			update(true)
		case <-wg.Wait():
			return errors.New("WireGuard device stopped unexpectedly")
		}
	}
}

func validateProfile(p config.Profile) error {
	if len(p.Secret) != 32 || len(p.WirePrivate) != 32 || len(p.PairID) != 64 || !validPublic(p.PeerWirePublic) || !validPublic(p.PeerRelayPublic) {
		return errors.New("invalid paired profile; pair again")
	}
	if _, err := hex.DecodeString(p.PairID); err != nil {
		return errors.New("invalid pair ID")
	}
	a, errA := netip.ParseAddr(p.LocalIP)
	b, errB := netip.ParseAddr(p.PeerIP)
	if errA != nil || errB != nil || a == b || !privateAddress(a) || !privateAddress(b) {
		return errors.New("invalid virtual addresses in profile")
	}
	return nil
}

type iceMessage struct {
	Generation string          `json:"generation"`
	Offer      transport.Offer `json:"offer"`
	Disabled   bool            `json:"disabled,omitempty"`
}

type activeICE struct{ agent *transport.ICE }

func (a *activeICE) replace(next *transport.ICE) {
	old := a.agent
	a.agent = next
	if old != nil {
		old.Close()
	}
}
func (a *activeICE) close() {
	if a.agent != nil {
		a.agent.Close()
		a.agent = nil
	}
}

func (c *Client) maintainDirect(ctx context.Context, p config.Profile, bind *transport.Bind, opts RunOptions) {
	active := &activeICE{}
	defer active.close()
	// The outer transport must never route through the virtual link it carries.
	// ICE gathering starts after TUN setup, so exclude both virtual endpoints
	// from local candidates and remote connectivity checks on every attempt.
	localIP, _ := netip.ParseAddr(p.LocalIP)
	peerIP, _ := netip.ParseAddr(p.PeerIP)
	excludedIPs := []netip.Addr{localIP, peerIP}
	stunURL := opts.STUNURL
	if stunURL == "" {
		u, _ := url.Parse(c.Server)
		stunURL = "stun:" + net.JoinHostPort(u.Hostname(), "3478")
	}
	delay := time.Second
	for ctx.Err() == nil {
		s, err := c.socket(ctx, "/v1/pairs/"+p.PairID+"/socket")
		if err == nil {
			err = s.waitPeer(ctx)
			if err == nil {
				var ch *channel
				ch, err = newChannel(ctx, s, p.Secret, p.Host, c.Server+"/pairs/"+p.PairID)
				if err == nil {
					err = runICENegotiation(ctx, ch, p.Host, stunURL, opts.RelayOnly, bind, active, excludedIPs...)
				}
			}
			s.close()
		}
		if ctx.Err() != nil {
			return
		}
		opts.Log.Debug("reconnecting rendezvous", "error", err)
		// Established direct paths are deliberately kept alive if signaling
		// disappears. Reconnecting control must not close a working tunnel.
		if !pause(ctx, delay) {
			return
		}
		delay = min(delay*2, 30*time.Second)
	}
}

func runICENegotiation(ctx context.Context, ch *channel, host bool, stunURL string, relayOnly bool, bind *transport.Bind, active *activeICE, excludedIPs ...netip.Addr) error {
	for ctx.Err() == nil {
		if host {
			for bind.Direct() {
				if !pause(ctx, time.Second) {
					return ctx.Err()
				}
			}
			var generation [16]byte
			if _, err := rand.Read(generation[:]); err != nil {
				return err
			}
			msg := iceMessage{Generation: hex.EncodeToString(generation[:]), Disabled: relayOnly}
			if relayOnly {
				if err := ch.send(ctx, msg); err != nil {
					return err
				}
				<-ctx.Done()
				return ctx.Err()
			}
			agent, err := transport.NewICE(ctx, stunURL, true, excludedIPs...)
			if err != nil {
				return err
			}
			attemptCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			msg.Offer, err = agent.LocalOffer(attemptCtx)
			if err == nil {
				err = ch.send(attemptCtx, msg)
			}
			var remote iceMessage
			if err == nil {
				err = ch.recv(attemptCtx, &remote)
			}
			if err == nil && remote.Generation != msg.Generation {
				err = errors.New("ICE generation mismatch")
			}
			var conn net.Conn
			if err == nil && !remote.Disabled {
				conn, err = agent.Connect(attemptCtx, remote.Offer)
			}
			cancel()
			if err == nil && conn != nil {
				if err := bind.SetDirect(conn); err != nil {
					agent.Close()
					return err
				}
				active.replace(agent)
			} else {
				agent.Close()
			}
			if err != nil {
				return err
			}
			if !pause(ctx, 10*time.Second) {
				return ctx.Err()
			}
		} else {
			var remote iceMessage
			if err := ch.recv(ctx, &remote); err != nil {
				return err
			}
			if len(remote.Generation) != 32 {
				return errors.New("invalid ICE generation")
			}
			if _, err := hex.DecodeString(remote.Generation); err != nil {
				return errors.New("invalid ICE generation")
			}
			if remote.Disabled {
				continue
			}
			msg := iceMessage{Generation: remote.Generation, Disabled: relayOnly}
			if relayOnly {
				if err := ch.send(ctx, msg); err != nil {
					return err
				}
				continue
			}
			agent, err := transport.NewICE(ctx, stunURL, false, excludedIPs...)
			if err != nil {
				return err
			}
			attemptCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			msg.Offer, err = agent.LocalOffer(attemptCtx)
			if err == nil {
				err = ch.send(attemptCtx, msg)
			}
			var conn net.Conn
			if err == nil {
				conn, err = agent.Connect(attemptCtx, remote.Offer)
			}
			cancel()
			if err == nil {
				if err := bind.SetDirect(conn); err != nil {
					agent.Close()
					return err
				}
				active.replace(agent)
			} else {
				agent.Close()
				return err
			}
		}
	}
	return ctx.Err()
}

func pause(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
