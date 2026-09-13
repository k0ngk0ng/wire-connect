//go:build windows && amd64

// Command wire-connect-helper-testutil exercises the unprivileged side of the
// Windows network helper. It is used only by the opt-in platform integration
// test and refuses to run with an elevated token so a test failure cannot
// silently exercise the native Wintun path in the child process.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/k0ngk0ng/wire-connect/internal/nethelper"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	defaultMTU         = 1420
	defaultPeerPort    = 39071
	testTimeout        = 30 * time.Second
	checkRetryInterval = 50 * time.Millisecond
)

type result struct {
	SID       string `json:"sid"`
	Elevated  bool   `json:"elevated"`
	Interface string `json:"interface"`
	Local     string `json:"local"`
	Peer      string `json:"peer"`
	Sent      bool   `json:"sent"`
	Received  bool   `json:"received"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return errors.New("network helper integration child must run with a non-elevated token")
	}
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("read child token SID: %w", err)
	}

	f := flag.NewFlagSet("wire-connect-helper-testutil", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	name := f.String("name", "", "helper-owned TUN name")
	localText := f.String("local", "", "local IPv4 address")
	peerText := f.String("peer", "", "peer IPv4 address")
	mtu := f.Int("mtu", defaultMTU, "TUN MTU")
	peerPort := f.Int("peer-port", defaultPeerPort, "fixed peer UDP port")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *name == "" || *localText == "" || *peerText == "" {
		return errors.New("usage: wire-connect-helper-testutil --name NAME --local IP --peer IP [--mtu MTU] [--peer-port PORT]")
	}
	local, err := netip.ParseAddr(*localText)
	if err != nil || !local.Is4() {
		return fmt.Errorf("invalid local IPv4 address %q", *localText)
	}
	peer, err := netip.ParseAddr(*peerText)
	if err != nil || !peer.Is4() {
		return fmt.Errorf("invalid peer IPv4 address %q", *peerText)
	}
	if *peerPort < 1 || *peerPort > 65535 {
		return fmt.Errorf("peer port %d is outside 1-65535", *peerPort)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if err := waitForHelper(ctx); err != nil {
		return err
	}

	cfg := nethelper.Config{
		Name:  *name,
		Local: local.String(),
		Peer:  peer.String(),
		MTU:   *mtu,
	}
	device, cleanup, err := nethelper.Open(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open helper TUN: %w", err)
	}
	if device == nil || cleanup == nil {
		return errors.New("open helper TUN returned an invalid device")
	}
	var closeErr error
	closed := false
	closeDevice := func() error {
		if !closed {
			closed = true
			closeErr = cleanup()
		}
		return closeErr
	}
	defer func() { _ = closeDevice() }()

	interfaceName, err := device.Name()
	if err != nil {
		return fmt.Errorf("read helper TUN name: %w", err)
	}
	if err := waitForTunnelUp(device); err != nil {
		return err
	}

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(local.AsSlice()), Port: 0})
	if err != nil {
		return fmt.Errorf("bind local UDP socket to %s: %w", local, err)
	}
	defer udp.Close()
	if err := udp.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set UDP deadline: %w", err)
	}
	localPort := udp.LocalAddr().(*net.UDPAddr).Port
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate UDP nonce: %w", err)
	}
	peerUDP := &net.UDPAddr{IP: net.IP(peer.AsSlice()), Port: *peerPort}
	if n, err := udp.WriteToUDP(nonce, peerUDP); err != nil {
		return fmt.Errorf("send UDP nonce through TUN: %w", err)
	} else if n != len(nonce) {
		return fmt.Errorf("send UDP nonce wrote %d bytes, want %d", n, len(nonce))
	}

	packet, err := readDevicePacket(ctx, device)
	if err != nil {
		return fmt.Errorf("read UDP packet from helper proxy: %w", err)
	}
	if err := validateUDP4Packet(packet, local, peer, uint16(localPort), uint16(*peerPort), nonce); err != nil {
		return fmt.Errorf("validate UDP packet from the OS: %w", err)
	}

	response := makeIPv4UDP(peer, local, uint16(*peerPort), uint16(localPort), nonce)
	frame := make([]byte, 64+len(response))
	copy(frame[64:], response)
	if n, err := device.Write([][]byte{frame}, 64); err != nil || n != 1 {
		return fmt.Errorf("inject reverse UDP packet through helper proxy: packets=%d error=%v", n, err)
	}
	got := make([]byte, 64<<10)
	n, from, err := udp.ReadFromUDP(got)
	if err != nil {
		return fmt.Errorf("receive reverse UDP packet from TUN: %w", err)
	}
	if from == nil || !from.IP.Equal(net.IP(peer.AsSlice())) || from.Port != *peerPort {
		return fmt.Errorf("reverse UDP peer = %v, want %s:%d", from, peer, *peerPort)
	}
	if n != len(nonce) || string(got[:n]) != string(nonce) {
		return fmt.Errorf("reverse UDP payload mismatch: got %d bytes", n)
	}
	if err := closeDevice(); err != nil {
		return fmt.Errorf("close helper TUN: %w", err)
	}

	return json.NewEncoder(os.Stdout).Encode(result{
		SID:       user.User.Sid.String(),
		Elevated:  token.IsElevated(),
		Interface: interfaceName,
		Local:     local.String(),
		Peer:      peer.String(),
		Sent:      true,
		Received:  true,
	})
}

func waitForHelper(ctx context.Context) error {
	var last error
	ticker := time.NewTicker(checkRetryInterval)
	defer ticker.Stop()
	for {
		if err := nethelper.Check(ctx); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for privileged network helper: %w (last check: %v)", ctx.Err(), last)
		case <-ticker.C:
		}
	}
}

func waitForTunnelUp(device tun.Device) error {
	select {
	case event, ok := <-device.Events():
		if !ok {
			return errors.New("helper TUN event stream closed before it became ready")
		}
		if event != tun.EventUp {
			return fmt.Errorf("helper TUN initial event = %v, want up", event)
		}
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("timed out waiting for helper TUN to become ready")
	}
}

type packetResult struct {
	packet []byte
	err    error
}

func readDevicePacket(ctx context.Context, device tun.Device) ([]byte, error) {
	result := make(chan packetResult, 1)
	go func() {
		buf := make([]byte, 64+65535)
		sizes := make([]int, 1)
		n, err := device.Read([][]byte{buf}, sizes, 64)
		if err != nil {
			result <- packetResult{err: err}
			return
		}
		if n != 1 || sizes[0] < 0 || sizes[0] > len(buf)-64 {
			result <- packetResult{err: fmt.Errorf("helper proxy read returned packet count %d and size %d", n, sizes[0])}
			return
		}
		result <- packetResult{packet: append([]byte(nil), buf[64:64+sizes[0]]...)}
	}()
	select {
	case r := <-result:
		return r.packet, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func validateUDP4Packet(packet []byte, src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) error {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return errors.New("packet is not an IPv4 UDP packet")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || ihl+8 > len(packet) {
		return errors.New("invalid IPv4 header length")
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total < ihl+8 || total > len(packet) {
		return fmt.Errorf("invalid IPv4 total length %d for %d-byte packet", total, len(packet))
	}
	if packet[9] != 17 {
		return fmt.Errorf("IPv4 protocol = %d, want UDP", packet[9])
	}
	if netip.AddrFrom4([4]byte(packet[12:16])).Unmap() != src || netip.AddrFrom4([4]byte(packet[16:20])).Unmap() != dst {
		return errors.New("IPv4 endpoints do not match the helper pair")
	}
	udp := packet[ihl:total]
	if len(udp) < 8 {
		return errors.New("truncated UDP header")
	}
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength < 8 || udpLength > len(udp) {
		return errors.New("invalid UDP length")
	}
	if binary.BigEndian.Uint16(udp[0:2]) != srcPort || binary.BigEndian.Uint16(udp[2:4]) != dstPort {
		return fmt.Errorf("UDP ports = %d -> %d, want %d -> %d", binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4]), srcPort, dstPort)
	}
	if string(udp[8:udpLength]) != string(payload) {
		return errors.New("UDP payload does not match nonce")
	}
	return nil
}

func makeIPv4UDP(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], src.AsSlice())
	copy(packet[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(src, dst, udp))
	return packet
}

func udpChecksum(src, dst netip.Addr, packet []byte) uint16 {
	var pseudo [12]byte
	copy(pseudo[0:4], src.AsSlice())
	copy(pseudo[4:8], dst.AsSlice())
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)))
	checksumValue := checksum(pseudo[:], packet)
	if checksumValue == 0 {
		return 0xffff
	}
	return checksumValue
}

func checksum(parts ...[]byte) uint16 {
	var sum uint32
	for _, part := range parts {
		for len(part) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(part[:2]))
			part = part[2:]
		}
		if len(part) == 1 {
			sum += uint32(part[0]) << 8
		}
		for sum>>16 != 0 {
			sum = (sum & 0xffff) + (sum >> 16)
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
