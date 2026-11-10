package monban

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// normalizeHostname validates a hostname, lowercases it, and removes a trailing dot.
func normalizeHostname(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" || len(s) > 253 {
		return "", fmt.Errorf("invalid hostname")
	}

	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid hostname")
		}

		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid hostname")
			}
		}
	}

	// Reject ambiguous legacy numeric IP forms.
	numeric := true
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c == '.') {
			numeric = false
		}
	}

	if numeric {
		return "", fmt.Errorf("invalid IP address")
	}

	return s, nil
}

// parseHostPort splits, validates, and normalizes a destination or rule address.
func parseHostPort(s string) (string, string, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", "", err
	}

	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("invalid port")
	}

	if ip, err := netip.ParseAddr(h); err == nil {
		if ip.Zone() != "" {
			return "", "", fmt.Errorf("IP zones are not supported")
		}

		return ip.Unmap().String(), strconv.Itoa(n), nil
	}

	h, err = normalizeHostname(h)
	return h, strconv.Itoa(n), err
}
