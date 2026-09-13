package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/control"
	"github.com/k0ngk0ng/wire-connect/internal/platform"
	"github.com/k0ngk0ng/wire-connect/internal/secure"
	"tailscale.com/types/key"
)

type PairOptions struct {
	Code    string
	Host    bool
	Network netip.Prefix
	OnCode  func(string)
	// AddressCheck is used by portable integration tests that do not own the
	// host routing table. Normal clients always use platform.Available.
	AddressCheck func(context.Context, ...netip.Addr) error
}

type identity struct {
	WirePublic  string `json:"wire_public"`
	RelayPublic string `json:"relay_public"`
}

type addressProposal struct {
	Local    string `json:"local"`
	Peer     string `json:"peer"`
	Accepted bool   `json:"accepted"`
}

func (c *Client) Pair(ctx context.Context, opts PairOptions) (config.Profile, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	var code secure.Code
	var err error
	if opts.Code == "" {
		if !opts.Host {
			return config.Profile{}, errors.New("joining requires a pairing code")
		}
		code, err = secure.GenerateCode()
	} else {
		code, err = secure.ParseCode(opts.Code)
	}
	if err != nil {
		return config.Profile{}, err
	}
	if opts.Host {
		created := false
		for attempts := 0; attempts < 8; attempts++ {
			err = c.request(ctx, "POST", "/v1/rooms", control.CreateRoomRequest{ID: code.Room()}, nil)
			var api *APIError
			if opts.Code == "" && errors.As(err, &api) && api.Status == 409 {
				code, err = secure.GenerateCode()
				if err != nil {
					return config.Profile{}, err
				}
				continue
			}
			created = err == nil
			break
		}
		if err != nil {
			return config.Profile{}, err
		}
		if !created {
			return config.Profile{}, errors.New("could not allocate a pairing room; try again")
		}
		if opts.OnCode != nil {
			opts.OnCode(code.String())
		}
	}
	role := "guest"
	if opts.Host {
		role = "host"
	}
	s, err := c.socket(ctx, "/v1/rooms/"+code.Room()+"/socket?role="+role)
	if err != nil {
		return config.Profile{}, err
	}
	defer s.close()
	if err := s.waitPeer(ctx); err != nil {
		return config.Profile{}, err
	}
	secret, err := secure.Pair(ctx, code, opts.Host, c.Server, pakeExchange{s})
	if err != nil {
		return config.Profile{}, fmt.Errorf("pairing authentication failed: %w", err)
	}
	pairID := secure.PairID(secret)
	ch, err := newChannel(ctx, s, secret, opts.Host, c.Server+"/pairs/"+pairID)
	if err != nil {
		return config.Profile{}, err
	}
	wire := key.NewNode()
	relay := key.NewNode()
	mine := identity{WirePublic: wire.Public().UntypedHexString(), RelayPublic: relay.Public().UntypedHexString()}
	if err := ch.send(ctx, mine); err != nil {
		return config.Profile{}, err
	}
	var peer identity
	if err := ch.recv(ctx, &peer); err != nil {
		return config.Profile{}, err
	}
	if !validPublic(peer.WirePublic) || !validPublic(peer.RelayPublic) || peer.WirePublic == mine.WirePublic || peer.RelayPublic == mine.RelayPublic {
		return config.Profile{}, errors.New("peer sent an invalid or reflected identity")
	}
	local, remote, err := negotiateAddresses(ctx, ch, opts)
	if err != nil {
		return config.Profile{}, err
	}
	// Both parties must durably commit the same authenticated pair ID before
	// either considers pairing complete. The short room can then expire.
	for {
		var result control.CommitResponse
		if err := c.request(ctx, "POST", "/v1/rooms/"+code.Room()+"/commit", control.CommitRequest{PairID: pairID}, &result); err != nil {
			return config.Profile{}, err
		}
		if result.Committed {
			break
		}
		select {
		case <-ctx.Done():
			return config.Profile{}, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	private := wire.Raw32()
	relayText, _ := relay.MarshalText()
	return config.Profile{Server: c.Server, PairID: pairID, Host: opts.Host, Secret: secret, WirePrivate: private[:], RelayPrivate: string(relayText), PeerWirePublic: peer.WirePublic, PeerRelayPublic: peer.RelayPublic, LocalIP: local.String(), PeerIP: remote.String()}, nil
}

func validPublic(s string) bool {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return false
	}
	var nonzero byte
	for _, v := range b {
		nonzero |= v
	}
	return nonzero != 0
}

func negotiateAddresses(ctx context.Context, ch *channel, opts PairOptions) (netip.Addr, netip.Addr, error) {
	check := opts.AddressCheck
	if check == nil {
		check = platform.Available
	}
	network := opts.Network
	if !network.IsValid() {
		network = netip.MustParsePrefix("100.64.0.0/10")
	}
	if !network.Addr().Is4() || network.Bits() > 30 || network.Bits() < 8 || !privateAddress(network.Addr()) || !privateAddress(prefixLast(network)) {
		return netip.Addr{}, netip.Addr{}, errors.New("--network must be an IPv4 private or shared-address prefix between /8 and /30")
	}
	for attempt := 0; attempt < 32; attempt++ {
		if opts.Host {
			local, peer, err := randomPair(network)
			if err != nil {
				return netip.Addr{}, netip.Addr{}, err
			}
			if err := check(ctx, local, peer); err != nil {
				continue
			}
			if err := ch.send(ctx, addressProposal{Local: local.String(), Peer: peer.String()}); err != nil {
				return netip.Addr{}, netip.Addr{}, err
			}
			var reply addressProposal
			if err := ch.recv(ctx, &reply); err != nil {
				return netip.Addr{}, netip.Addr{}, err
			}
			if reply.Accepted {
				return local, peer, nil
			}
		} else {
			var proposal addressProposal
			if err := ch.recv(ctx, &proposal); err != nil {
				return netip.Addr{}, netip.Addr{}, err
			}
			host, err1 := netip.ParseAddr(proposal.Local)
			guest, err2 := netip.ParseAddr(proposal.Peer)
			if err1 != nil || err2 != nil || host == guest || !privateAddress(host) || !privateAddress(guest) {
				return netip.Addr{}, netip.Addr{}, errors.New("peer proposed invalid virtual addresses")
			}
			accepted := check(ctx, guest, host) == nil
			if err := ch.send(ctx, addressProposal{Accepted: accepted}); err != nil {
				return netip.Addr{}, netip.Addr{}, err
			}
			if accepted {
				return guest, host, nil
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, errors.New("could not find unused virtual addresses; choose another private range with --network")
}

func privateAddress(ip netip.Addr) bool {
	return ip.Is4() && (ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip))
}
func prefixLast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	n := binary.BigEndian.Uint32(b[:]) | uint32((uint64(1)<<uint(32-p.Bits()))-1)
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}
func randomPair(p netip.Prefix) (netip.Addr, netip.Addr, error) {
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	base := p.Masked().Addr().As4()
	mask := uint32((uint64(1) << uint(32-p.Bits())) - 1)
	n := binary.BigEndian.Uint32(base[:]) | (binary.BigEndian.Uint32(random[:]) & mask &^ uint32(3))
	var a, b [4]byte
	binary.BigEndian.PutUint32(a[:], n+1)
	binary.BigEndian.PutUint32(b[:], n+2)
	return netip.AddrFrom4(a), netip.AddrFrom4(b), nil
}
