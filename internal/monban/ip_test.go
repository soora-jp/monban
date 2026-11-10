package monban

import (
	"net/netip"
	"testing"
)

func TestBuiltInIPBans(t *testing.T) {
	p := policy{}
	for _, s := range []string{
		"0.0.0.0", "0.255.255.255", "10.1.2.3", "100.64.0.1", "100.127.255.255",
		"127.0.0.1", "127.255.255.255", "169.254.169.254", "172.16.0.1", "172.31.255.255",
		"192.0.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.19.255.255",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::127.0.0.1", "::ffff:127.0.0.1", "::ffff:10.1.2.3",
		"64:ff9b::7f00:1", "64:ff9b:1::1", "100::1", "2001::1", "2001:2::1",
		"2001:db8::1", "2002:7f00:1::1", "3fff::1", "fc00::1", "fd00::1", "fe80::1", "fec0::", "fec0::1", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ff02::1",
	} {
		t.Run(s, func(t *testing.T) {
			if p.allowsIP("internal.example.com", netip.MustParseAddr(s)) {
				t.Fatal("built-in banned IP allowed")
			}
		})
	}

	for _, s := range []string{"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		t.Run(s, func(t *testing.T) {
			if !p.allowsIP("internal.example.com", netip.MustParseAddr(s)) {
				t.Fatal("public IP rejected")
			}
		})
	}

	if p.allowsIP("internal.example.com", netip.Addr{}) || p.allowsIP("internal.example.com", netip.MustParseAddr("fe80::1%eth0")) {
		t.Fatal("invalid or scoped address allowed")
	}
}

func TestAdditionalBansAndPinholes(t *testing.T) {
	p := policy{bannedIPs: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}}
	if p.allowsIP("internal.example.com", netip.MustParseAddr("8.8.8.8")) || p.allowsIP("internal.example.com", netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("additional bans replaced or bypassed built-in bans")
	}

	p.pinholes = []pinhole{
		{host: "internal.example.com", prefix: netip.MustParsePrefix("127.0.0.1/32")},
		{host: "internal.example.com", prefix: netip.MustParsePrefix("8.8.8.8/32")},
		{host: "internal.example.com", prefix: netip.MustParsePrefix("fd12:3456::/48")},
	}
	for _, s := range []string{"127.0.0.1", "::ffff:127.0.0.1", "8.8.8.8", "fd12:3456::1234"} {
		if !p.allowsIP("internal.example.com", netip.MustParseAddr(s)) {
			t.Errorf("pinhole did not allow %s", s)
		}
	}

	for _, s := range []string{"127.0.0.2", "10.0.0.1", "8.8.8.9", "fd12:3457::1"} {
		if p.allowsIP("internal.example.com", netip.MustParseAddr(s)) {
			t.Errorf("pinhole was too broad: %s", s)
		}
	}
}

func TestParseIPPrefix(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"10.1.2.3", "10.1.2.3/32"},
		{"10.1.2.3/8", "10.0.0.0/8"},
		{"fd00::1", "fd00::1/128"},
		{"fd00::abcd/64", "fd00::/64"},
		{"::ffff:127.0.0.1", "127.0.0.1/32"},
		{"::ffff:127.0.0.1/128", "127.0.0.1/32"},
		{"::ffff:192.168.1.1/120", "192.168.1.0/24"},
	} {
		got, err := parseIPPrefix(tc.input)
		if err != nil || got.String() != tc.want {
			t.Errorf("%s: got %s, %v; want %s", tc.input, got, err, tc.want)
		}
	}

	for _, s := range []string{"", "example.com", "127.0.0.1:80", "[::1]", "fe80::1%eth0", "10.0.0.0/33", "::ffff:127.0.0.1/95"} {
		if _, err := parseIPPrefix(s); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}

func TestParsePinhole(t *testing.T) {
	for _, tc := range []struct{ input, host, prefix string }{
		{"sqs.ap-northeast-1.amazonaws.com=10.1.0.0/16", "sqs.ap-northeast-1.amazonaws.com", "10.1.0.0/16"},
		{"Internal.Example.COM.=10.1.2.3", "internal.example.com", "10.1.2.3/32"},
		{"internal.example.com=fd00::1", "internal.example.com", "fd00::1/128"},
		{"internal.example.com=::ffff:127.0.0.1/128", "internal.example.com", "127.0.0.1/32"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			hole, err := parsePinhole(tc.input)
			if err != nil || hole.host != tc.host || hole.prefix.String() != tc.prefix {
				t.Fatalf("hole=%+v err=%v", hole, err)
			}
		})
	}

	for _, input := range []string{
		"10.1.0.0/16",
		"=10.1.0.0/16",
		"internal.example.com=",
		"*.example.com=10.1.0.0/16",
		"127.0.0.1=10.1.0.0/16",
		"localhost=10.1.0.0/16",
		"internal.example.com:443=10.1.0.0/16",
		"internal.example.com=10.1.0.0/33",
		"internal.example.com=fe80::1%eth0",
		"internal.example.com=10.1.0.1=extra",
	} {
		if _, err := parsePinhole(input); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}

func TestPinholeIsScopedToFQDN(t *testing.T) {
	hole, err := parsePinhole("SQS.ap-northeast-1.amazonaws.com.=10.1.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	p := policy{pinholes: []pinhole{hole}}
	ip := netip.MustParseAddr("10.1.2.3")
	if !p.allowsIP("sqs.ap-northeast-1.amazonaws.com", ip) {
		t.Fatal("pinhole did not apply to its FQDN")
	}

	for _, host := range []string{"other.example.com", "sub.sqs.ap-northeast-1.amazonaws.com", "amazonaws.com"} {
		if p.allowsIP(host, ip) {
			t.Errorf("pinhole leaked to %s", host)
		}
	}

	if p.allowsIP(hole.host, netip.MustParseAddr("10.2.0.1")) {
		t.Fatal("pinhole leaked outside its CIDR")
	}
	if p.allowed(hole.host, "443") {
		t.Fatal("pinhole created an allow rule")
	}
}
