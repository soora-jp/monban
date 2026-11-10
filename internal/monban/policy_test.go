package monban

import "testing"

func testPolicy(t *testing.T, entries ...string) policy {
	t.Helper()

	p := policy{}
	for _, s := range entries {
		r, err := parseRule(s)
		if err != nil {
			t.Fatal(err)
		}

		p.rules = append(p.rules, r)
	}

	return p
}

func TestPolicy(t *testing.T) {
	for _, tc := range []struct {
		rule, host, port string
		match            bool
	}{
		{"*.example.com:443", "a.example.com", "443", true},
		{"*.example.com:443", "a.b.example.com", "443", false},
		{"*.example.com:443", "example.com", "443", false},
		{"**.example.com:443", "a.b.example.com", "443", true},
		{"**.example.com:443", "example.com", "443", false},
		{"**.example.com:443", "badexample.com", "443", false},
		{"Example.COM.:443", "example.com", "443", true},
		{"example.com:443", "example.com", "80", false},
		{"example.com:443", "127.0.0.1", "443", false},
	} {
		t.Run(tc.rule+tc.host+tc.port, func(t *testing.T) {
			p := testPolicy(t, tc.rule)
			if got := p.allowed(tc.host, tc.port); got != tc.match {
				t.Fatalf("allowed=%t want %t", got, tc.match)
			}
		})
	}

	for _, s := range []string{
		"api*.example.com:443",
		"127.0.0.1:443",
		"[::1]:443",
		"[::ffff:127.0.0.1]:443",
		"localhost:443",
		"*:443",
		"*.127.0.0.1:443",
		"example.com:0",
		"example.com:65536",
		"example.com",
		"a..com:443",
		"127.1:443",
		"[fe80::1%eth0]:443",
	} {
		if _, err := parseRule(s); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}
