package platform

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func checkCandidateRoutes(ips []netip.Addr, routes []netip.Prefix) error {
	for _, ip := range ips {
		for _, route := range routes {
			// A /0 is intentionally ignored even if a platform parser returns
			// one.  The virtual address can safely be more specific than the
			// host's default route.
			if route.Bits() == 0 {
				continue
			}
			if route.Contains(ip) {
				return fmt.Errorf("wire-connect: address %s overlaps existing route %s", ip, route)
			}
		}
	}
	return nil
}

// parseIPv4Prefix parses the canonical CIDR form emitted by Linux and
// Windows.  It returns skip=true for defaults and IPv6 entries.
func parseIPv4Prefix(value string) (prefix netip.Prefix, skip bool, err error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "default") {
		return netip.Prefix{}, true, nil
	}
	if strings.Contains(value, ":") {
		return netip.Prefix{}, true, nil
	}
	if strings.Contains(value, "/") {
		prefix, err = netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, false, fmt.Errorf("parse IPv4 route %q: %w", value, err)
		}
		if !prefix.Addr().Is4() {
			return netip.Prefix{}, true, nil
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return netip.Prefix{}, true, nil
		}
		return prefix, false, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf("parse IPv4 route %q: %w", value, err)
	}
	if !addr.Is4() {
		return netip.Prefix{}, true, nil
	}
	if addr.IsUnspecified() {
		return netip.Prefix{}, true, nil
	}
	return netip.PrefixFrom(addr, 32), false, nil
}

// parseDarwinIPv4Prefix accepts both CIDR output and the abbreviated network
// notation used by netstat (for example, 192.168.1 means /24 and 10 means
// /8).  netstat -f inet does not print IPv6 destinations, but unknown colon
// entries are skipped defensively.
func parseDarwinIPv4Prefix(value string) (prefix netip.Prefix, skip bool, err error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "default") || strings.Contains(value, ":") {
		return netip.Prefix{}, true, nil
	}
	base := value
	bits := -1
	if slash := strings.LastIndexByte(value, '/'); slash >= 0 {
		base = value[:slash]
		bits, err = strconv.Atoi(value[slash+1:])
		if err != nil || bits < 0 || bits > 32 {
			return netip.Prefix{}, false, fmt.Errorf("parse Darwin IPv4 route %q: invalid prefix length", value)
		}
	}

	addr, components, err := parseDarwinIPv4Address(base)
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf("parse Darwin IPv4 route %q: %w", value, err)
	}
	if bits < 0 {
		bits = components * 8
		if components == 4 {
			bits = 32
		}
	}
	if addr.IsUnspecified() || bits == 0 {
		return netip.Prefix{}, true, nil
	}
	return netip.PrefixFrom(addr, bits).Masked(), false, nil
}

func parseDarwinIPv4Address(value string) (netip.Addr, int, error) {
	parts := strings.Split(value, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Addr{}, 0, fmt.Errorf("invalid IPv4 destination")
	}
	var octets [4]byte
	for i, part := range parts {
		if part == "" {
			return netip.Addr{}, 0, fmt.Errorf("invalid IPv4 destination")
		}
		value, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return netip.Addr{}, 0, fmt.Errorf("invalid IPv4 destination")
		}
		octets[i] = byte(value)
	}
	return netip.AddrFrom4(octets), len(parts), nil
}

func parseDarwinRoutePrefixes(data []byte) ([]netip.Prefix, error) {
	var routes []netip.Prefix
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || isDarwinRouteHeader(fields[0]) {
			continue
		}
		prefix, skip, err := parseDarwinIPv4Prefix(fields[0])
		if err != nil {
			// netstat can include link# pseudo destinations in the table;
			// they are interface metadata, not IPv4 prefixes.
			if strings.Contains(fields[0], "#") {
				continue
			}
			return nil, err
		}
		if !skip {
			routes = append(routes, prefix)
		}
	}
	return routes, nil
}

func isDarwinRouteHeader(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "routing", "routing:", "tables", "internet", "internet:", "internet6", "internet6:", "destination", "destination:":
		return true
	default:
		return false
	}
}

type linuxRouteEntry struct {
	Destination string `json:"dst"`
}

func parseLinuxRoutePrefixes(data []byte) ([]netip.Prefix, error) {
	var entries []linuxRouteEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse Linux route JSON: %w", err)
	}
	return parseRouteEntries(entries)
}

func parseRouteEntries(entries []linuxRouteEntry) ([]netip.Prefix, error) {
	routes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, skip, err := parseIPv4Prefix(entry.Destination)
		if err != nil {
			return nil, err
		}
		if skip {
			continue
		}
		routes = append(routes, prefix)
	}
	return routes, nil
}

type windowsRouteEntry struct {
	DestinationPrefix string `json:"DestinationPrefix"`
}

func parseWindowsRoutePrefixes(data []byte) ([]netip.Prefix, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var entries []windowsRouteEntry
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
			return nil, fmt.Errorf("parse Windows route JSON: %w", err)
		}
	} else {
		var entry windowsRouteEntry
		if err := json.Unmarshal([]byte(trimmed), &entry); err != nil {
			return nil, fmt.Errorf("parse Windows route JSON: %w", err)
		}
		entries = []windowsRouteEntry{entry}
	}
	routes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, skip, err := parseIPv4Prefix(entry.DestinationPrefix)
		if err != nil {
			return nil, err
		}
		if !skip {
			routes = append(routes, prefix)
		}
	}
	return routes, nil
}
