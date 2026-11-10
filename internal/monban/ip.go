package monban

import (
	"fmt"
	"net/netip"
	"strings"
)

// These ranges are always included. Flags can add bans or explicit pinholes,
// but cannot replace the built-in list.
var builtInIPBans = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),

	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// parseIPPrefix accepts an IP or CIDR and normalizes mapped IPv4 to IPv4.
func parseIPPrefix(s string) (netip.Prefix, error) {
	if ip, err := netip.ParseAddr(s); err == nil {
		if ip.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("IP zones are not supported")
		}

		ip = ip.Unmap()
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}

	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}

	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("mapped IPv4 prefix must be /96 or narrower")
		}

		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}

	return prefix.Masked(), nil
}

type pinhole struct {
	host   string
	prefix netip.Prefix
}

// parsePinhole binds an exact FQDN to an IP exception. It does not allow the FQDN.
func parsePinhole(s string) (pinhole, error) {
	host, network, ok := strings.Cut(s, "=")
	if !ok {
		return pinhole{}, fmt.Errorf("expected FQDN=IP/CIDR")
	}

	host, err := normalizeHostname(host)
	if err != nil {
		return pinhole{}, err
	}

	if !strings.Contains(host, ".") {
		return pinhole{}, fmt.Errorf("pinhole requires a fully qualified domain name")
	}

	prefix, err := parseIPPrefix(network)
	if err != nil {
		return pinhole{}, err
	}

	return pinhole{host: host, prefix: prefix}, nil
}

func (p policy) allowsIP(host string, ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}

	for _, hole := range p.pinholes {
		if hole.host == host && hole.prefix.Contains(ip) {
			return true
		}
	}

	for _, prefix := range builtInIPBans {
		if prefix.Contains(ip) {
			return false
		}
	}

	for _, prefix := range p.bannedIPs {
		if prefix.Contains(ip) {
			return false
		}
	}

	return true
}
