package monban

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

var errDenied = errors.New("destination denied")

type rule struct {
	host string
	port string
}

type policy struct {
	rules     []rule
	bannedIPs []netip.Prefix
	pinholes  []pinhole
}

func parseRule(s string) (rule, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return rule{}, err
	}

	// Only whole, leading wildcard labels are supported.
	prefix := ""
	if strings.HasPrefix(h, "**.") {
		prefix = "**."
		h = strings.TrimPrefix(h, prefix)
	} else if strings.HasPrefix(h, "*.") {
		prefix = "*."
		h = strings.TrimPrefix(h, prefix)
	}

	h, p, err = parseHostPort(net.JoinHostPort(h, p))
	if err != nil {
		return rule{}, err
	}

	if _, err := netip.ParseAddr(h); err == nil {
		return rule{}, fmt.Errorf("allow rules require FQDN:port, not an IP address")
	}

	if !strings.Contains(h, ".") {
		return rule{}, fmt.Errorf("allow rules require a fully qualified domain name")
	}

	return rule{prefix + h, p}, nil
}

func (p policy) allowed(host, port string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}

	for _, r := range p.rules {
		if r.port != port {
			continue
		}

		if r.host == host {
			return true
		}

		if strings.HasPrefix(r.host, "*.") || strings.HasPrefix(r.host, "**.") {
			if _, err := netip.ParseAddr(host); err == nil {
				continue
			}

			_, suffix, _ := strings.Cut(r.host, ".")
			if !strings.HasSuffix(host, "."+suffix) {
				continue
			}

			prefix := strings.TrimSuffix(host, "."+suffix)
			if strings.HasPrefix(r.host, "**.") || !strings.Contains(prefix, ".") {
				return true
			}
		}
	}

	return false
}
