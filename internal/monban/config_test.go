package monban

import (
	"errors"
	"flag"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInvalidConfig(t *testing.T) {
	clearConfigEnvironment(t)

	for _, args := range [][]string{
		{"--unknown"},
		{"--allow", "127.0.0.1:443"},
		{"--allow", "[::1]:443"},
		{"--allow", "localhost:443"},
		{"--add-ban-ip", "example.com"},
		{"--add-ban-ip", "10.0.0.0/33"},
		{"--pinhole", "example.com:443"},
		{"--pinhole", "internal.example.com=fe80::1%eth0"},
		{"--pinhole", "10.1.0.0/16"},
		{"--pinhole", "*.example.com=10.1.0.0/16"},
		{"--allow", "example.com"},
		{"--dns-server", "dns.example.com:53"},
		{"--dns-server", "127.0.0.1:0"},
		{"unexpected"},
		{"--max-connections", "0"},
		{"--max-header-bytes", "0"},
		{"--tcp-buffer-size", "-1"},
		{"--connect-timeout", "0s"},
		{"--dns-timeout", "-1s"},
		{"--header-timeout", "0s"},
		{"--request-timeout", "0s"},
		{"--idle-timeout", "0s"},
		{"--tunnel-timeout", "-1s"},
		{"--shutdown-timeout", "0s"},
		{"--shutdown-delay", "-1s"},
	} {
		if _, err := parseConfig(args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

func TestAllowlistConfig(t *testing.T) {
	clearConfigEnvironment(t)

	c, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}

	if c.policy.allowed("example.com", "443") || c.policy.allowed("127.0.0.1", "443") {
		t.Fatal("empty allowlist allowed a destination")
	}

	c, err = parseConfig([]string{"--allow", "example.com:443", "--allow", "other.example.com:80"})
	if err != nil {
		t.Fatal(err)
	}

	if !c.policy.allowed("example.com", "443") || !c.policy.allowed("other.example.com", "80") {
		t.Fatal("explicit destination not allowed")
	}

	if c.policy.allowed("example.com", "80") || c.policy.allowed("other.example.com", "443") {
		t.Fatal("unlisted destination allowed")
	}
}

func TestIPFilterConfig(t *testing.T) {
	clearConfigEnvironment(t)

	c, err := parseConfig([]string{
		"--allow", "internal.example.com:443",
		"--add-ban-ip", "8.8.8.8",
		"--add-ban-ip", "9.9.9.0/24",
		"--pinhole", "internal.example.com=::ffff:127.0.0.1",
		"--pinhole", "internal.example.com=fd00::/64",
	})
	if err != nil {
		t.Fatal(err)
	}

	if c.policy.allowsIP("internal.example.com", netip.MustParseAddr("8.8.8.8")) ||
		c.policy.allowsIP("internal.example.com", netip.MustParseAddr("9.9.9.9")) ||
		c.policy.allowsIP("internal.example.com", netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("missing additional or built-in ban")
	}

	if !c.policy.allowsIP("internal.example.com", netip.MustParseAddr("127.0.0.1")) ||
		!c.policy.allowsIP("internal.example.com", netip.MustParseAddr("fd00::1")) {
		t.Fatal("pinhole not applied")
	}

	if c.policy.allowsIP("other.example.com", netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("pinhole leaked to another FQDN")
	}

	if !c.policy.allowed("internal.example.com", "443") || c.policy.allowed("127.0.0.1", "443") {
		t.Fatal("IP filter changed FQDN allow semantics")
	}
}

func clearConfigEnvironment(t *testing.T) {
	t.Helper()

	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "MONBAN_") {
			t.Setenv(name, "")
		}
	}
}

func TestConfigEnvironment(t *testing.T) {
	clearConfigEnvironment(t)

	for name, value := range map[string]string{
		"MONBAN_LISTEN":           "127.0.0.1:8080",
		"MONBAN_ADMIN_LISTEN":     "127.0.0.1:9091",
		"MONBAN_DNS_SERVER":       "127.0.0.1:5353",
		"MONBAN_MAX_CONNECTIONS":  "42",
		"MONBAN_MAX_HEADER_BYTES": "8192",
		"MONBAN_CONNECT_TIMEOUT":  "11s",
		"MONBAN_DNS_TIMEOUT":      "3s",
		"MONBAN_HEADER_TIMEOUT":   "12s",
		"MONBAN_REQUEST_TIMEOUT":  "2m",
		"MONBAN_IDLE_TIMEOUT":     "45s",
		"MONBAN_TUNNEL_TIMEOUT":   "0",
		"MONBAN_SHUTDOWN_DELAY":   "2s",
		"MONBAN_SHUTDOWN_TIMEOUT": "7s",
		"MONBAN_ALLOW":            " api.example.com:443, internal.example.com:8443 ",
		"MONBAN_ADD_BAN_IP":       "8.8.8.8, 9.9.9.0/24",
		"MONBAN_PINHOLE":          "internal.example.com=10.1.0.0/16,internal.example.com=fd00::/64",
	} {
		t.Setenv(name, value)
	}

	c, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}

	if c.listen != "127.0.0.1:8080" || c.adminListen != "127.0.0.1:9091" || c.dnsServer != "127.0.0.1:5353" {
		t.Fatalf("unexpected addresses: %+v", c)
	}

	want := options{
		maxConnections:  42,
		tcpBufferSize:   256 << 10,
		maxHeaderBytes:  8192,
		connectTimeout:  11 * time.Second,
		dnsTimeout:      3 * time.Second,
		headerTimeout:   12 * time.Second,
		requestTimeout:  2 * time.Minute,
		idleTimeout:     45 * time.Second,
		tunnelTimeout:   0,
		shutdownDelay:   2 * time.Second,
		shutdownTimeout: 7 * time.Second,
	}

	if c.options != want {
		t.Fatalf("options=%+v want %+v", c.options, want)
	}

	if !c.policy.allowed("api.example.com", "443") || !c.policy.allowed("internal.example.com", "8443") {
		t.Fatal("environment allowlist not applied")
	}

	if c.policy.allowsIP("api.example.com", netip.MustParseAddr("8.8.8.8")) ||
		c.policy.allowsIP("api.example.com", netip.MustParseAddr("9.9.9.9")) {
		t.Fatal("environment bans not applied")
	}

	if !c.policy.allowsIP("internal.example.com", netip.MustParseAddr("10.1.2.3")) ||
		!c.policy.allowsIP("internal.example.com", netip.MustParseAddr("fd00::1")) {
		t.Fatal("environment pinholes not applied")
	}

	if c.policy.allowsIP("api.example.com", netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("environment pinhole leaked to another FQDN")
	}
}

func TestCLIOverridesEnvironment(t *testing.T) {
	clearConfigEnvironment(t)

	for name, value := range map[string]string{
		"MONBAN_LISTEN":           "127.0.0.1:8080",
		"MONBAN_ADMIN_LISTEN":     "127.0.0.1:9091",
		"MONBAN_DNS_SERVER":       "invalid",
		"MONBAN_MAX_CONNECTIONS":  "invalid",
		"MONBAN_MAX_HEADER_BYTES": "invalid",
		"MONBAN_CONNECT_TIMEOUT":  "invalid",
		"MONBAN_DNS_TIMEOUT":      "invalid",
		"MONBAN_HEADER_TIMEOUT":   "invalid",
		"MONBAN_REQUEST_TIMEOUT":  "invalid",
		"MONBAN_IDLE_TIMEOUT":     "invalid",
		"MONBAN_TUNNEL_TIMEOUT":   "1h",
		"MONBAN_SHUTDOWN_DELAY":   "invalid",
		"MONBAN_SHUTDOWN_TIMEOUT": "invalid",
		"MONBAN_ALLOW":            "env.example.com:443,extra.example.com:443",
		"MONBAN_ADD_BAN_IP":       "9.9.9.9,1.1.1.1",
		"MONBAN_PINHOLE":          "env.example.com=10.0.0.0/8,cli.example.com=192.168.0.0/16",
	} {
		t.Setenv(name, value)
	}

	c, err := parseConfig([]string{
		"--listen", "127.0.0.1:8888",
		"--admin-listen", "127.0.0.1:9090",
		"--dns-server", "127.0.0.1:53",
		"--max-connections", "12",
		"--max-header-bytes", "16384",
		"--connect-timeout", "10s",
		"--dns-timeout", "5s",
		"--header-timeout", "10s",
		"--request-timeout", "5m",
		"--idle-timeout", "60s",
		"--tunnel-timeout", "0",
		"--shutdown-delay", "0",
		"--shutdown-timeout", "10s",
		"--allow", "cli.example.com:443",
		"--allow", "another.example.com:443",
		"--add-ban-ip", "8.8.8.8",
		"--pinhole", "cli.example.com=10.1.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}

	if c.listen != "127.0.0.1:8888" || c.adminListen != "127.0.0.1:9090" || c.dnsServer != "127.0.0.1:53" {
		t.Fatalf("unexpected addresses: %+v", c)
	}

	want := defaultOptions()
	want.maxConnections = 12
	want.tunnelTimeout = 0
	want.shutdownDelay = 0
	if c.options != want {
		t.Fatalf("options=%+v want %+v", c.options, want)
	}

	if c.policy.allowed("env.example.com", "443") || c.policy.allowed("extra.example.com", "443") {
		t.Fatal("environment allowlist was merged into CLI allowlist")
	}

	if !c.policy.allowed("cli.example.com", "443") || !c.policy.allowed("another.example.com", "443") {
		t.Fatal("repeated CLI flags not retained")
	}

	if c.policy.allowsIP("cli.example.com", netip.MustParseAddr("8.8.8.8")) ||
		!c.policy.allowsIP("cli.example.com", netip.MustParseAddr("9.9.9.9")) {
		t.Fatal("CLI bans did not replace environment bans")
	}

	if !c.policy.allowsIP("cli.example.com", netip.MustParseAddr("10.1.2.3")) ||
		c.policy.allowsIP("cli.example.com", netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("CLI pinholes did not replace environment pinholes")
	}
}

func TestInvalidConfigEnvironment(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"MONBAN_MAX_CONNECTIONS", "invalid"},
		{"MONBAN_MAX_CONNECTIONS", "0"},
		{"MONBAN_MAX_HEADER_BYTES", "-1"},
		{"MONBAN_DNS_TIMEOUT", "invalid"},
		{"MONBAN_SHUTDOWN_DELAY", "-1s"},
		{"MONBAN_REQUEST_TIMEOUT", "-1s"},
		{"MONBAN_ALLOW", "127.0.0.1:443"},
		{"MONBAN_ALLOW", "valid.example.com:443,"},
		{"MONBAN_ADD_BAN_IP", "example.com"},
		{"MONBAN_PINHOLE", "10.1.0.0/16"},
		{"MONBAN_DNS_SERVER", "dns.example.com:53"},
	} {
		t.Run(tc.name+"="+tc.value, func(t *testing.T) {
			clearConfigEnvironment(t)
			t.Setenv(tc.name, tc.value)
			if _, err := parseConfig(nil); err == nil {
				t.Fatal("invalid environment value accepted")
			}
		})
	}
}

func TestCLIBypassesInvalidEnvironmentRules(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("MONBAN_ALLOW", "invalid")
	t.Setenv("MONBAN_ADD_BAN_IP", "invalid")
	t.Setenv("MONBAN_PINHOLE", "invalid")

	_, err := parseConfig([]string{
		"--allow", "api.example.com:443",
		"--add-ban-ip", "8.8.8.8",
		"--pinhole", "api.example.com=10.1.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEmptyConfigEnvironment(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("MONBAN_ALLOW", "   ")
	t.Setenv("MONBAN_MAX_CONNECTIONS", "")
	t.Setenv("MONBAN_LISTEN", " ")

	c, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(c.policy.rules) != 0 || c.options != defaultOptions() || c.listen != "0.0.0.0:8888" {
		t.Fatalf("empty environment changed defaults: %+v", c)
	}
}

func TestHelpDoesNotValidateEnvironment(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("MONBAN_MAX_CONNECTIONS", "invalid")
	if _, err := parseConfig([]string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatal(err)
	}
}

func TestPartialCLIOverride(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("MONBAN_LISTEN", "127.0.0.1:8080")
	t.Setenv("MONBAN_MAX_CONNECTIONS", "42")
	t.Setenv("MONBAN_ALLOW", "api.example.com:443,internal.example.com:443")

	c, err := parseConfig([]string{"--listen", "127.0.0.1:8888"})
	if err != nil {
		t.Fatal(err)
	}

	if c.listen != "127.0.0.1:8888" || c.options.maxConnections != 42 {
		t.Fatalf("partial override failed: %+v", c)
	}

	if !c.policy.allowed("api.example.com", "443") || !c.policy.allowed("internal.example.com", "443") {
		t.Fatal("unrelated CLI flag discarded environment allowlist")
	}
}

func TestHelpOptionPrefixes(t *testing.T) {
	fs := flag.NewFlagSet("monban", flag.ContinueOnError)
	var output strings.Builder
	fs.SetOutput(&output)
	fs.String("allow", "", "allowed FQDN:port")
	fs.String("listen", ":8888", "proxy address")
	fs.Int("max-connections", 42, "maximum connections")
	fs.Bool("v", false, "version output")

	printUsage(fs)
	help := output.String()
	for _, text := range []string{"Usage of monban:", "  --allow string", "  --max-connections int", "(default 42)", "  -v\t"} {
		if !strings.Contains(help, text) {
			t.Errorf("missing help text %q in:\n%s", text, help)
		}
	}

	if strings.Contains(help, "  -allow") || strings.Contains(help, "  --v\t") {
		t.Fatalf("incorrect option prefixes:\n%s", help)
	}

	previous := -1
	for _, text := range []string{
		"Policy:\n",
		"  --allow string",
		"Network:\n",
		"  --listen string",
		"Limits and timeouts:\n",
		"  --max-connections int",
		"Other:\n",
		"  -v\t",
	} {
		position := strings.Index(help, text)
		if position <= previous {
			t.Fatalf("help group order is incorrect at %q:\n%s", text, help)
		}
		if strings.Count(help, text) != 1 {
			t.Fatalf("missing or repeated help entry %q:\n%s", text, help)
		}
		previous = position
	}

	if fs.Output() != &output {
		t.Fatal("help changed the flag output destination")
	}
}

func TestTCPBufferConfig(t *testing.T) {
	clearConfigEnvironment(t)
	for _, tc := range []struct {
		name string
		env  string
		args []string
		want int
	}{
		{"default", "", nil, 256 << 10},
		{"environment", "131072", nil, 128 << 10},
		{"CLI precedence", "invalid", []string{"--tcp-buffer-size=524288"}, 512 << 10},
		{"OS defaults", "", []string{"--tcp-buffer-size=0"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MONBAN_TCP_BUFFER_SIZE", tc.env)
			c, err := parseConfig(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if c.options.tcpBufferSize != tc.want || c.options.maxConnections != 32 {
				t.Fatalf("unexpected options: %+v", c.options)
			}
		})
	}
}

func TestLogLevelConfig(t *testing.T) {
	clearConfigEnvironment(t)
	for _, tc := range []struct {
		name, env string
		args      []string
		want      string
	}{
		{"default", "", nil, "info"},
		{"environment", "warn", nil, "warn"},
		{"CLI priority", "invalid", []string{"--log-level=ERROR"}, "error"},
		{"debug", "", []string{"--log-level=debug"}, "debug"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MONBAN_LOG_LEVEL", tc.env)
			c, err := parseConfig(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if c.logLevel != tc.want {
				t.Fatalf("level=%s want %s", c.logLevel, tc.want)
			}
		})
	}
	t.Setenv("MONBAN_LOG_LEVEL", "invalid")
	if _, err := parseConfig(nil); err == nil {
		t.Fatal("accepted invalid log level")
	}
}

func TestVersionFlag(t *testing.T) {
	clearConfigEnvironment(t)

	// --version works even when other settings are invalid.
	t.Setenv("MONBAN_MAX_CONNECTIONS", "invalid")
	if _, err := parseConfig([]string{"--version"}); !errors.Is(err, errVersion) {
		t.Fatalf("--version: %v", err)
	}

	// The environment cannot turn a normal start into a version request.
	t.Setenv("MONBAN_MAX_CONNECTIONS", "")
	t.Setenv("MONBAN_VERSION", "true")
	if _, err := parseConfig(nil); err != nil {
		t.Fatalf("MONBAN_VERSION: %v", err)
	}
}
