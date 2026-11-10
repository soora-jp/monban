package monban

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestResolveDestinationPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rules   []string
		host    string
		denied  bool
		queries int
	}{
		{"deny before DNS", nil, "start.test", true, 0},
		{"allowed FQDN", []string{"start.test:443"}, "start.test", false, 1},
		{"FQDN allow does not allow IP", []string{"start.test:443"}, "127.0.0.1", true, 0},
		{"unlisted literal IP", nil, "127.0.0.1", true, 0},
		{"different port", []string{"start.test:80"}, "start.test", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queries := 0
			r := proxy{
				options: defaultOptions(),
				metrics: newMetrics(),
				policy:  testPolicy(t, tc.rules...),
				lookupIP: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
					queries++
					if network != "ip" || host != "start.test." {
						t.Fatalf("unexpected lookup: %s %s", network, host)
					}

					if _, ok := ctx.Deadline(); !ok {
						t.Error("lookup has no deadline")
					}

					return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
				},
			}

			ips, err := r.resolveDestination(context.Background(), tc.host, "443")
			if tc.denied {
				if !errors.Is(err, errDenied) {
					t.Fatalf("expected denial, got %v", err)
				}
			} else if err != nil || len(ips) != 1 {
				t.Fatalf("ips=%v err=%v", ips, err)
			}

			if queries != tc.queries {
				t.Fatalf("queries=%d want %d", queries, tc.queries)
			}
		})
	}
}

func TestResolveDestinationFailure(t *testing.T) {
	failure := errors.New("lookup failed")
	for _, lookupErr := range []error{nil, failure} {
		r := proxy{
			options:  defaultOptions(),
			metrics:  newMetrics(),
			policy:   testPolicy(t, "start.test:443"),
			lookupIP: func(context.Context, string, string) ([]netip.Addr, error) { return nil, lookupErr },
		}

		if _, err := r.resolveDestination(context.Background(), "start.test", "443"); err == nil {
			t.Fatal("accepted failed or empty lookup")
		}
	}
}

func TestResolvedIPBans(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []string
		ban       string
		pinhole   string
		denied    bool
	}{
		{name: "private", addresses: []string{"10.0.0.1"}, denied: true},
		{name: "loopback", addresses: []string{"127.0.0.1"}, denied: true},
		{name: "ULA", addresses: []string{"fd00::1"}, denied: true},
		{name: "mixed answers", addresses: []string{"8.8.8.8", "127.0.0.1"}, denied: true},
		{name: "mapped loopback", addresses: []string{"::ffff:127.0.0.1"}, denied: true},
		{name: "additional ban", addresses: []string{"8.8.8.8"}, ban: "8.8.8.0/24", denied: true},
		{name: "public", addresses: []string{"8.8.8.8", "2606:4700:4700::1111"}},
		{name: "pinhole", addresses: []string{"8.8.8.8", "127.0.0.1"}, pinhole: "127.0.0.1/32"},
		{name: "mapped pinhole", addresses: []string{"::ffff:127.0.0.1"}, pinhole: "127.0.0.1/32"},
		{name: "pinhole does not exempt other IPs", addresses: []string{"127.0.0.1", "10.0.0.1"}, pinhole: "127.0.0.1/32", denied: true},
		{name: "pinhole overrides additional ban", addresses: []string{"8.8.8.8"}, ban: "8.8.8.0/24", pinhole: "8.8.8.8/32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy(t, "start.test:443")
			if tc.ban != "" {
				p.bannedIPs = []netip.Prefix{netip.MustParsePrefix(tc.ban)}
			}

			if tc.pinhole != "" {
				p.pinholes = []pinhole{{host: "start.test", prefix: netip.MustParsePrefix(tc.pinhole)}}
			}

			r := proxy{
				options: defaultOptions(),
				metrics: newMetrics(),
				policy:  p,
				lookupIP: func(context.Context, string, string) ([]netip.Addr, error) {
					var ips []netip.Addr
					for _, s := range tc.addresses {
						ips = append(ips, netip.MustParseAddr(s))
					}

					return ips, nil
				},
			}

			ips, err := r.resolveDestination(context.Background(), "start.test", "443")
			if tc.denied {
				if !errors.Is(err, errDenied) || len(ips) != 0 {
					t.Fatalf("ips=%v err=%v", ips, err)
				}
			} else {
				if err != nil || len(ips) != len(tc.addresses) {
					t.Fatalf("ips=%v err=%v", ips, err)
				}

				for _, ip := range ips {
					if ip.Is4In6() {
						t.Errorf("mapped IP not normalized: %s", ip)
					}
				}
			}
		})
	}
}

func TestPinholeDoesNotAllowUnlistedNamesOrIPs(t *testing.T) {
	p := testPolicy(t, "start.test:443")
	p.pinholes = []pinhole{{host: "start.test", prefix: netip.MustParsePrefix("0.0.0.0/0")}, {host: "start.test", prefix: netip.MustParsePrefix("::/0")}}
	r := proxy{
		options: defaultOptions(),
		metrics: newMetrics(),
		policy:  p,
		lookupIP: func(context.Context, string, string) ([]netip.Addr, error) {
			t.Error("rejected destination triggered DNS")
			return nil, nil
		},
	}
	for _, host := range []string{"other.test", "127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		if _, err := r.resolveDestination(context.Background(), host, "443"); !errors.Is(err, errDenied) {
			t.Errorf("%s: %v", host, err)
		}
	}
}

func TestResolvePinholeIsScopedToRequestedFQDN(t *testing.T) {
	p := testPolicy(t, "sqs.ap-northeast-1.amazonaws.com:443", "other.example.com:443")
	hole, err := parsePinhole("sqs.ap-northeast-1.amazonaws.com=10.1.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	p.pinholes = []pinhole{hole}

	r := proxy{
		options: defaultOptions(),
		metrics: newMetrics(),
		policy:  p,
		lookupIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
		},
	}

	ips, err := r.resolveDestination(context.Background(), hole.host, "443")
	if err != nil || len(ips) != 1 {
		t.Fatalf("matching FQDN: ips=%v err=%v", ips, err)
	}

	if _, err := r.resolveDestination(context.Background(), "other.example.com", "443"); !errors.Is(err, errDenied) {
		t.Fatalf("same IP through different FQDN: %v", err)
	}
	if _, err := r.resolveDestination(context.Background(), hole.host, "80"); !errors.Is(err, errDenied) {
		t.Fatalf("unlisted port: %v", err)
	}
}
