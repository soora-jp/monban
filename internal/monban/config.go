package monban

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

type options struct {
	maxConnections  int
	tcpBufferSize   int
	maxHeaderBytes  int
	connectTimeout  time.Duration
	dnsTimeout      time.Duration
	headerTimeout   time.Duration
	requestTimeout  time.Duration
	idleTimeout     time.Duration
	tunnelTimeout   time.Duration
	shutdownDelay   time.Duration
	shutdownTimeout time.Duration
}

func defaultOptions() options {
	return options{
		maxConnections:  32,
		tcpBufferSize:   256 << 10,
		maxHeaderBytes:  16 << 10,
		connectTimeout:  10 * time.Second,
		dnsTimeout:      5 * time.Second,
		headerTimeout:   10 * time.Second,
		requestTimeout:  5 * time.Minute,
		idleTimeout:     60 * time.Second,
		tunnelTimeout:   time.Hour,
		shutdownDelay:   5 * time.Second,
		shutdownTimeout: 10 * time.Second,
	}
}

type config struct {
	logLevel    string
	listen      string
	adminListen string
	dnsServer   string
	policy      policy
	options     options
}

func parseConfig(args []string) (config, error) {
	c := config{options: defaultOptions()}

	fs := flag.NewFlagSet("monban", flag.ContinueOnError)
	fs.Usage = func() { printUsage(fs) }
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.StringVar(&c.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	fs.StringVar(&c.listen, "listen", "0.0.0.0:8888", "proxy listen address")
	fs.StringVar(&c.adminListen, "admin-listen", "0.0.0.0:9090", "health and metrics listen address")
	o := &c.options
	fs.IntVar(&o.maxConnections, "max-connections", o.maxConnections, "maximum open client connections")
	fs.IntVar(&o.tcpBufferSize, "tcp-buffer-size", o.tcpBufferSize, "TCP receive and send buffer bytes per socket; zero uses OS defaults")
	fs.IntVar(&o.maxHeaderBytes, "max-header-bytes", o.maxHeaderBytes, "maximum request and upstream response header bytes")
	fs.DurationVar(&o.connectTimeout, "connect-timeout", o.connectTimeout, "total DNS and upstream connection setup timeout")
	fs.DurationVar(&o.dnsTimeout, "dns-timeout", o.dnsTimeout, "DNS lookup timeout")
	fs.DurationVar(&o.headerTimeout, "header-timeout", o.headerTimeout, "incoming and upstream HTTP header timeout")
	fs.DurationVar(&o.requestTimeout, "request-timeout", o.requestTimeout, "HTTP request timeout, including request and response bodies")
	fs.DurationVar(&o.idleTimeout, "idle-timeout", o.idleTimeout, "idle HTTP connection and inactive tunnel timeout")
	fs.DurationVar(&o.tunnelTimeout, "tunnel-timeout", o.tunnelTimeout, "maximum tunnel lifetime; zero disables")
	fs.DurationVar(&o.shutdownDelay, "shutdown-delay", o.shutdownDelay, "delay after becoming unready before stopping new connections")
	fs.DurationVar(&o.shutdownTimeout, "shutdown-timeout", o.shutdownTimeout, "HTTP shutdown grace period")
	dnsServer := fs.String("dns-server", "", "DNS server IP:port (default: system resolver configuration)")

	var allow, banIP, pinhole []string
	fs.Func("allow", "allowed FQDN:port; repeatable", func(s string) error {
		allow = append(allow, s)
		return nil
	})

	fs.Func("add-ban-ip", "additional banned IP or CIDR; repeatable", func(s string) error {
		banIP = append(banIP, s)
		return nil
	})

	fs.Func("pinhole", "FQDN=IP/CIDR exception to IP bans; repeatable", func(s string) error {
		pinhole = append(pinhole, s)
		return nil
	})

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	if *showVersion {
		return config{}, errVersion
	}

	if err := applyEnvironment(fs); err != nil {
		return config{}, err
	}

	c.logLevel = strings.ToLower(c.logLevel)
	switch c.logLevel {
	case "debug", "info", "warn", "error":
	default:
		return config{}, fmt.Errorf("invalid log level %q: use debug, info, warn, or error", c.logLevel)
	}

	if o.maxConnections < 1 ||
		o.maxHeaderBytes < 1 ||
		o.tcpBufferSize < 0 ||
		o.connectTimeout <= 0 ||
		o.dnsTimeout <= 0 ||
		o.headerTimeout <= 0 ||
		o.requestTimeout <= 0 ||
		o.idleTimeout <= 0 ||
		o.tunnelTimeout < 0 ||
		o.shutdownTimeout <= 0 ||
		o.shutdownDelay < 0 {
		return config{}, fmt.Errorf("connection and header limits and timeouts must be positive; TCP buffer size, tunnel timeout and shutdown delay may be zero")
	}

	if fs.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected positional arguments")
	}

	p := policy{}

	for _, s := range allow {
		r, err := parseRule(s)
		if err != nil {
			return config{}, fmt.Errorf("rule %q: %w", s, err)
		}

		p.rules = append(p.rules, r)
	}

	for _, s := range banIP {
		prefix, err := parseIPPrefix(s)
		if err != nil {
			return config{}, fmt.Errorf("add-ban-ip %q: %w", s, err)
		}

		p.bannedIPs = append(p.bannedIPs, prefix)
	}

	for _, s := range pinhole {
		hole, err := parsePinhole(s)
		if err != nil {
			return config{}, fmt.Errorf("pinhole %q: %w", s, err)
		}

		p.pinholes = append(p.pinholes, hole)
	}

	server, err := parseDNSServerAddress(*dnsServer)
	if err != nil {
		return config{}, err
	}

	c.policy = p
	c.dnsServer = server

	return c, nil
}

// parseDNSServerAddress validates and normalizes an optional literal IP:port.
// It does not perform a DNS lookup.
func parseDNSServerAddress(s string) (string, error) {
	if s == "" {
		return "", nil
	}

	host, port, err := parseHostPort(s)
	if err != nil {
		return "", err
	}

	if _, err := netip.ParseAddr(host); err != nil {
		return "", fmt.Errorf("DNS server must use a literal IP")
	}

	return net.JoinHostPort(host, port), nil
}

func flagEnvName(name string) string {
	return "MONBAN_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// applyEnvironment fills only flags that were not explicitly set on the CLI.
func applyEnvironment(fs *flag.FlagSet) error {
	cliFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { cliFlags[f.Name] = true })

	var envErr error
	fs.VisitAll(func(f *flag.Flag) {
		if envErr != nil || cliFlags[f.Name] || f.Name == "version" {
			return
		}

		name := flagEnvName(f.Name)
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			return
		}

		values := []string{value}
		switch f.Name {
		case "allow", "add-ban-ip", "pinhole":
			values = strings.Split(value, ",")
		}

		for _, entry := range values {
			if err := fs.Set(f.Name, strings.TrimSpace(entry)); err != nil {
				envErr = fmt.Errorf("%s: %w", name, err)
				return
			}
		}
	})

	return envErr
}

// printUsage groups options while preserving Go's descriptions and defaults.
func printUsage(fs *flag.FlagSet) {
	output := fs.Output()
	var help strings.Builder
	fs.SetOutput(&help)
	fs.PrintDefaults()
	fs.SetOutput(output)

	blocks := make(map[string]string)
	var name string
	for _, line := range strings.SplitAfter(help.String(), "\n") {
		if strings.HasPrefix(line, "  -") {
			name = strings.TrimPrefix(strings.Fields(line)[0], "-")
			if len(name) > 1 {
				line = "  --" + strings.TrimPrefix(line, "  -")
			}
		}

		blocks[name] += line
	}

	fmt.Fprintf(output, "Usage of %s:\n", fs.Name())
	printGroup := func(title string, names []string) {
		var group strings.Builder
		for _, name := range names {
			group.WriteString(blocks[name])
			delete(blocks, name)
		}

		if group.Len() > 0 {
			fmt.Fprintf(output, "\n%s:\n%s", title, group.String())
		}
	}

	printGroup("Policy", []string{"allow", "add-ban-ip", "pinhole"})
	printGroup("General", []string{"version", "log-level"})
	printGroup("Network", []string{"listen", "admin-listen", "dns-server"})
	printGroup("Limits and timeouts", []string{
		"max-connections",
		"tcp-buffer-size",
		"max-header-bytes",
		"connect-timeout",
		"dns-timeout",
		"header-timeout",
		"request-timeout",
		"idle-timeout",
		"tunnel-timeout",
		"shutdown-delay",
		"shutdown-timeout",
	})

	// Keep newly added or short options visible even before assigning a group.
	var other []string
	fs.VisitAll(func(f *flag.Flag) {
		if _, ok := blocks[f.Name]; ok {
			other = append(other, f.Name)
		}
	})
	printGroup("Other", other)
}
