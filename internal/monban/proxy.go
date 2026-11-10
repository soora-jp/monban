package monban

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const tunnelBufferSize = 32 << 10

var errUpstreamLimit = errors.New("upstream connection limit reached")

var dialer = net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}

type proxy struct {
	policy        policy
	options       options
	metrics       *metrics
	ready         atomic.Bool
	slots         chan struct{}
	upstreamSlots chan struct{}
	transport     *http.Transport
	forwarder     *httputil.ReverseProxy
	lookupIP      func(context.Context, string, string) ([]netip.Addr, error)
	ctx           context.Context
	cancel        context.CancelFunc
}

func newProxy(p policy, dnsServer string, o options) *proxy {
	ctx, cancel := context.WithCancel(context.Background())
	dns := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, _, addr string) (net.Conn, error) {
			if dnsServer != "" {
				addr = dnsServer
			}

			return dialTCP(ctx, addr, o.tcpBufferSize)
		},
	}

	x := &proxy{
		policy:        p,
		options:       o,
		slots:         make(chan struct{}, o.maxConnections),
		upstreamSlots: make(chan struct{}, 2*o.maxConnections),
		metrics:       newMetrics(),
		lookupIP:      dns.LookupNetIP,
		ctx:           ctx,
		cancel:        cancel,
	}

	x.transport = &http.Transport{
		DialContext:            x.dialUpstream,
		MaxConnsPerHost:        o.maxConnections,
		MaxIdleConns:           o.maxConnections,
		IdleConnTimeout:        o.idleTimeout,
		ResponseHeaderTimeout:  o.headerTimeout,
		DisableCompression:     true,
		MaxResponseHeaderBytes: int64(o.maxHeaderBytes),
	}

	x.forwarder = &httputil.ReverseProxy{
		Transport:    x.transport,
		ErrorLog:     slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
		Rewrite:      func(r *httputil.ProxyRequest) { r.Out.Host = r.Out.URL.Host },
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) { x.writeError(w, err, "http") },
	}

	return x
}

func (p *proxy) dialUpstream(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := parseHostPort(addr)
	if err != nil {
		return nil, err
	}

	if !p.policy.allowed(host, port) {
		slog.Debug("destination denied", "host", host, "port", port, "reason", "allowlist")
		return nil, errDenied
	}

	ctx, cancel := context.WithTimeout(ctx, p.options.connectTimeout)
	defer cancel()

	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()

	// Bound detached Transport dials as well as connected and pooled sockets.
	select {
	case p.upstreamSlots <- struct{}{}:
	default:
		p.metrics.errors.WithLabelValues("dial").Inc()
		return nil, errUpstreamLimit
	}

	connected := false
	release := sync.OnceFunc(func() { <-p.upstreamSlots })
	defer func() {
		if !connected {
			release()
		}
	}()

	ips, err := p.resolveDestination(ctx, host, port)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		c, e := dialTCP(ctx, net.JoinHostPort(ip.String(), port), p.options.tcpBufferSize)
		if e == nil {
			slog.Debug("upstream connected", "host", host, "port", port, "ip", ip.String())
			connected = true
			return &meteredConn{
				Conn:     c,
				sent:     p.metrics.bytes.WithLabelValues("sent"),
				received: p.metrics.bytes.WithLabelValues("received"),
				release:  release,
			}, nil
		}
		err = e
	}

	p.metrics.errors.WithLabelValues("dial").Inc()
	return nil, err
}

func (p *proxy) writeError(w http.ResponseWriter, err error, protocol string) {
	if errors.Is(err, errDenied) {
		p.metrics.denied.WithLabelValues(protocol).Inc()
		http.Error(w, "destination denied", http.StatusForbidden)
		return
	}

	p.metrics.errors.WithLabelValues(protocol).Inc()
	slog.Error("upstream error", "protocol", protocol, "error", err)
	status := http.StatusBadGateway
	if errors.Is(err, errUpstreamLimit) {
		status = http.StatusServiceUnavailable
	}
	http.Error(w, "upstream connection failed", status)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	protocol := "http"
	if r.Method == http.MethodConnect {
		protocol = "connect"
	}

	p.metrics.requests.WithLabelValues(protocol).Inc()
	p.metrics.active.Inc()
	start := time.Now()
	defer func() {
		p.metrics.active.Dec()
		p.metrics.duration.WithLabelValues(protocol).Observe(time.Since(start).Seconds())
	}()

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil || r.Header.Get("Upgrade") != "" {
		p.metrics.invalid.WithLabelValues("http").Inc()
		http.Error(w, "use an absolute http URL or CONNECT", http.StatusBadRequest)
		return
	}

	port := r.URL.Port()
	if port == "" {
		port = "80"
	}

	host, port, err := parseHostPort(net.JoinHostPort(r.URL.Hostname(), port))
	if err != nil {
		p.metrics.invalid.WithLabelValues("http").Inc()
		http.Error(w, "invalid destination", http.StatusBadRequest)
		return
	}

	if !p.policy.allowed(host, port) {
		slog.Debug("destination denied", "host", host, "port", port, "reason", "allowlist")
		p.writeError(w, errDenied, "http")
		return
	}

	r.URL.Host = net.JoinHostPort(host, port)
	ctx, cancel := context.WithTimeout(r.Context(), p.options.requestTimeout)
	defer cancel()

	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(p.options.requestTimeout))
	_ = controller.SetWriteDeadline(time.Now().Add(p.options.requestTimeout))
	p.forwarder.ServeHTTP(w, r.WithContext(ctx))
}

func (p *proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := parseHostPort(r.RequestURI)
	if err != nil {
		p.metrics.invalid.WithLabelValues("connect").Inc()
		http.Error(w, "CONNECT requires host:port", http.StatusBadRequest)
		return
	}

	upstream, err := p.dialUpstream(r.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		p.writeError(w, err, "connect")
		return
	}

	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT unsupported", http.StatusInternalServerError)
		return
	}

	client, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}

	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(p.options.idleTimeout))

	stop := context.AfterFunc(p.ctx, func() {
		_ = client.Close()
		_ = upstream.Close()
	})

	defer stop()

	if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	if err = buffer.Flush(); err != nil {
		return
	}

	p.metrics.tunnels.Inc()
	defer p.metrics.tunnels.Dec()

	if p.options.tunnelTimeout > 0 {
		timer := time.AfterFunc(p.options.tunnelTimeout, func() {
			_ = client.Close()
			_ = upstream.Close()
		})

		defer timer.Stop()
	}

	_ = client.SetDeadline(time.Now().Add(p.options.idleTimeout))
	_ = upstream.SetDeadline(time.Now().Add(p.options.idleTimeout))

	tunnelClient := &idleTimeoutConn{
		Conn:    &bufferedConn{Conn: client, reader: buffer},
		timeout: p.options.idleTimeout,
	}

	tunnelUpstream := &idleTimeoutConn{Conn: upstream, timeout: p.options.idleTimeout}

	done := make(chan struct{})
	go func() {
		_, err := io.CopyBuffer(tunnelUpstream, tunnelClient, make([]byte, tunnelBufferSize))
		if err != nil {
			p.recordTunnelError(err)
			_ = upstream.Close()
			_ = client.Close()
		} else if tcp, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = tcp.CloseWrite()
		}

		close(done)
	}()

	if _, err := io.CopyBuffer(tunnelClient, tunnelUpstream, make([]byte, tunnelBufferSize)); err != nil {
		p.recordTunnelError(err)
		_ = client.Close()
		_ = upstream.Close()
	} else if tcp, ok := client.(interface{ CloseWrite() error }); ok {
		_ = tcp.CloseWrite()
	}

	<-done
}

// recordTunnelError excludes normal termination from alerting counters.
func (p *proxy) recordTunnelError(err error) {
	if err == nil || p.ctx.Err() != nil ||
		errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return
	}

	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return
	}

	p.metrics.errors.WithLabelValues("tunnel").Inc()
}
