package monban

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"
)

// resolveDestination rejects destinations outside the allowlist before DNS lookup.
func (p *proxy) resolveDestination(ctx context.Context, host, port string) ([]netip.Addr, error) {
	if !p.policy.allowed(host, port) {
		slog.Debug("destination denied", "host", host, "port", port, "reason", "allowlist")
		return nil, errDenied
	}

	ctx, cancel := context.WithTimeout(ctx, p.options.dnsTimeout)
	defer cancel()

	// An absolute name avoids search-domain queries for an allowed destination.
	start := time.Now()
	p.metrics.dns.Inc()
	defer func() { p.metrics.dnsDuration.Observe(time.Since(start).Seconds()) }()

	ips, err := p.lookupIP(ctx, "ip", host+".")
	if err != nil {
		p.metrics.errors.WithLabelValues("dns").Inc()
		return nil, err
	}

	if len(ips) == 0 {
		p.metrics.errors.WithLabelValues("dns").Inc()
		return nil, fmt.Errorf("no addresses for %s", host)
	}

	for i, ip := range ips {
		ips[i] = ip.Unmap()
		if !p.policy.allowsIP(host, ips[i]) {
			slog.Debug("destination denied", "host", host, "port", port, "ip", ips[i].String(), "reason", "banned_ip")
			return nil, errDenied
		}
	}

	return ips, nil
}
