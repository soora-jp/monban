package monban

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestProxyWithAdmin(t *testing.T, p policy, o options) (*proxy, *httptest.Server, *httptest.Server) {
	t.Helper()

	x := newProxy(p, "127.0.0.1:1", o)
	setTestUpstreamResolver(x)
	s := httptest.NewUnstartedServer(x)
	s.Listener = &limitedListener{Listener: s.Listener, slots: x.slots, metrics: x.metrics}
	s.Config.ReadHeaderTimeout = o.headerTimeout
	s.Config.MaxHeaderBytes = o.maxHeaderBytes
	s.Config.IdleTimeout = o.idleTimeout
	s.Start()
	x.ready.Store(true)
	admin := httptest.NewUnstartedServer(x.adminHandler())
	admin.Listener = &limitedListener{Listener: admin.Listener, slots: make(chan struct{}, maxAdminConnections)}
	admin.Config.MaxHeaderBytes = 8 << 10
	admin.Config.ReadHeaderTimeout = 5 * time.Second
	admin.Config.IdleTimeout = 30 * time.Second
	admin.Start()
	t.Cleanup(func() {
		x.cancel()
		x.transport.CloseIdleConnections()
		s.Close()
		admin.Close()
	})

	return x, s, admin
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}

		time.Sleep(time.Millisecond)
	}

	t.Fatal("condition did not become true")
}

func getStatus(t *testing.T, target string) int {
	t.Helper()

	client := http.Client{Timeout: time.Second}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestConnectionLimitAndHealth(t *testing.T) {
	o := defaultOptions()
	o.maxConnections = 1
	x, s, admin := newTestProxyWithAdmin(t, testPolicy(t), o)
	if status := getStatus(t, admin.URL+"/readyz"); status != 200 {
		t.Fatal(status)
	}

	first, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	defer first.Close()

	eventually(t, func() bool { return len(x.slots) == 1 })
	second, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	defer second.Close()

	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = second.Read(make([]byte, 1)); err == nil {
		t.Fatal("over-limit connection was not closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("over-limit connection timed out instead of closing")
	}

	if status := getStatus(t, admin.URL+"/readyz"); status != 503 {
		t.Fatal(status)
	}

	if status := getStatus(t, admin.URL+"/livez"); status != 200 {
		t.Fatal(status)
	}

	resp, err := http.Get(admin.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}

	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	for _, line := range []string{
		"monban_connections 1\n",
		"monban_connections_rejected_total 1\n",
		"go_goroutines ",
		"process_start_time_seconds ",
	} {
		if !strings.Contains(string(body), line) {
			t.Errorf("missing metric: %s", line)
		}
	}

	_ = first.Close()
	eventually(t, func() bool { return len(x.slots) == 0 })
	if status := getStatus(t, admin.URL+"/readyz"); status != 200 {
		t.Fatal(status)
	}

	x.ready.Store(false)
	if status := getStatus(t, admin.URL+"/readyz"); status != 503 {
		t.Fatal(status)
	}

	if status := getStatus(t, admin.URL+"/livez"); status != 200 {
		t.Fatal(status)
	}
}

func TestDecisionMetrics(t *testing.T) {
	_, s, admin := newTestProxyWithAdmin(t, testPolicy(t), defaultOptions())
	u, _ := url.Parse(s.URL)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()

	client := http.Client{Transport: tr, Timeout: time.Second}
	resp, err := client.Get("http://secret.example.test/")
	if err != nil {
		t.Fatal(err)
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Fatal(resp.Status)
	}

	if status := getStatus(t, s.URL+"/livez"); status != 400 {
		t.Fatal(status)
	}

	resp, err = http.Get(admin.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}

	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	body := string(b)
	for _, line := range []string{
		`monban_denied_total{protocol="http"} 1`,
		`monban_invalid_total{protocol="http"} 1`,
		"monban_dns_lookups_total 0",
		"monban_active_requests 0",
	} {
		if !strings.Contains(body, line) {
			t.Errorf("missing metric: %s", line)
		}
	}

	if strings.Contains(body, "secret.example.test") {
		t.Fatal("destination leaked into metrics")
	}
}

func newTestEchoListener(t *testing.T) net.Listener {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}

		accepted <- c
		defer c.Close()

		_, _ = io.Copy(c, c)
	}()

	t.Cleanup(func() {
		_ = l.Close()
		select {
		case c := <-accepted:
			_ = c.Close()
		default:
		}
	})

	return l
}

func openTunnel(t *testing.T, s *httptest.Server, target string) (net.Conn, *bufio.Reader) {
	t.Helper()

	c, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	reader := bufio.NewReader(c)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}

	return c, reader
}

func TestTunnelTimeouts(t *testing.T) {
	for _, mode := range []string{"idle", "lifetime"} {
		t.Run(mode, func(t *testing.T) {
			upstream := newTestEchoListener(t)
			o := defaultOptions()
			o.idleTimeout = 100 * time.Millisecond
			o.tunnelTimeout = 0
			if mode == "lifetime" {
				o.idleTimeout = time.Second
				o.tunnelTimeout = 100 * time.Millisecond
			}

			x, s, _ := newTestProxyWithAdmin(t, testUpstreamPolicy(t, upstream.Addr().String()), o)
			_, reader := openTunnel(t, s, testUpstreamAddress(t, upstream.Addr().String()))
			start := time.Now()
			if _, err := reader.ReadByte(); err == nil {
				t.Fatal("tunnel did not close")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("client deadline expired before proxy closed tunnel")
			}

			if time.Since(start) > time.Second {
				t.Fatal("timeout not enforced")
			}

			eventually(t, func() bool { return len(x.slots) == 0 })
			if count := testTunnelErrorCount(t, x); count != 0 {
				t.Fatalf("normal %s expiry counted as %v tunnel errors", mode, count)
			}
		})
	}
}

func TestTunnelActivityExtendsIdleDeadline(t *testing.T) {
	upstream := newTestEchoListener(t)
	o := defaultOptions()
	o.idleTimeout = 200 * time.Millisecond
	o.tunnelTimeout = 0
	_, s, admin := newTestProxyWithAdmin(t, testUpstreamPolicy(t, upstream.Addr().String()), o)
	c, reader := openTunnel(t, s, testUpstreamAddress(t, upstream.Addr().String()))
	for range 6 {
		time.Sleep(50 * time.Millisecond)
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}

		b := make([]byte, 4)
		if _, err := io.ReadFull(reader, b); err != nil || string(b) != "ping" {
			t.Fatalf("%q %v", b, err)
		}
	}

	resp, err := http.Get(admin.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}

	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	for _, line := range []string{
		`monban_upstream_bytes_total{direction="sent"} 24`,
		`monban_upstream_bytes_total{direction="received"} 24`,
		"monban_tunnels 1",
	} {
		if !strings.Contains(string(body), line) {
			t.Errorf("missing metric: %s", line)
		}
	}
}

func TestHTTPRequestTimeout(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		upstream.Close()
	})

	o := defaultOptions()
	o.requestTimeout = 100 * time.Millisecond
	_, s, _ := newTestProxyWithAdmin(t, testUpstreamPolicy(t, upstream.Listener.Addr().String()), o)
	u, _ := url.Parse(s.URL)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()

	client := http.Client{Transport: tr, Timeout: 2 * time.Second}
	start := time.Now()
	resp, err := client.Get("http://" + testUpstreamAddress(t, upstream.Listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}

	_, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if err == nil {
		t.Fatal("stalled response unexpectedly completed")
	}

	if time.Since(start) > time.Second {
		t.Fatal("request timeout was not enforced")
	}
}

func TestDNSAndConnectTimeouts(t *testing.T) {
	for _, stage := range []string{"dns", "connect"} {
		t.Run(stage, func(t *testing.T) {
			o := defaultOptions()
			o.dnsTimeout = 100 * time.Millisecond
			o.connectTimeout = time.Second
			if stage == "connect" {
				o.dnsTimeout = time.Second
				o.connectTimeout = 100 * time.Millisecond
			}

			x := newProxy(testPolicy(t, "slow.test:443"), "", o)
			defer x.cancel()
			defer x.transport.CloseIdleConnections()

			x.lookupIP = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}

			start := time.Now()
			_, err := x.dialUpstream(context.Background(), "tcp", "slow.test:443")
			if err == nil || time.Since(start) > time.Second {
				t.Fatalf("deadline not enforced: %v", err)
			}
		})
	}
}

func TestServeShutdown(t *testing.T) {
	// Reserve addresses, then let serve bind them. No external services are used.
	reserve := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}

		addr := l.Addr().String()
		_ = l.Close()
		return addr
	}

	listen, admin := reserve(), reserve()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	o := defaultOptions()
	o.shutdownDelay = 0
	done := make(chan error, 1)
	go func() { done <- serve(ctx, listen, admin, testPolicy(t), "", o) }()
	client := http.Client{Timeout: 100 * time.Millisecond}
	eventually(t, func() bool {
		resp, err := client.Get("http://" + admin + "/readyz")
		if err != nil {
			return false
		}

		defer resp.Body.Close()

		return resp.StatusCode == 200
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown timed out")
	}

	for _, addr := range []string{listen, admin} {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			t.Fatalf("listener remains open: %s", addr)
		}
	}
}

func TestHTTPUploadTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	defer upstream.Close()

	o := defaultOptions()
	o.requestTimeout = 100 * time.Millisecond
	_, s, _ := newTestProxyWithAdmin(t, testUpstreamPolicy(t, upstream.Listener.Addr().String()), o)
	c, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	_, _ = fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000\r\n\r\na", "http://"+testUpstreamAddress(t, upstream.Listener.Addr().String()), testUpstreamAddress(t, upstream.Listener.Addr().String()))
	// The incomplete upload must not hold the handler until the client's deadline.
	_, _ = io.ReadAll(c)
	if time.Since(start) > time.Second {
		t.Fatal("slow upload was not bounded by request timeout")
	}
}

func TestShutdownPreservesPendingDNSAndUpstreamDial(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	o := defaultOptions()
	o.shutdownDelay = 0
	o.shutdownTimeout = 2 * time.Second
	x, s, admin := newTestProxyWithAdmin(t, testUpstreamPolicy(t, upstream.Listener.Addr().String()), o)

	started := make(chan struct{})
	release := make(chan struct{})
	releaseLookup := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseLookup)
	x.lookupIP = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		close(started)
		select {
		case <-release:
			return []netip.Addr{x.policy.pinholes[0].prefix.Addr()}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	proxyURL, _ := url.Parse(s.URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	result := make(chan error, 1)
	go func() {
		resp, err := client.Get("http://" + testUpstreamAddress(t, upstream.Listener.Addr().String()))
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			err = readErr
			if err == nil && (resp.StatusCode != 200 || string(body) != "ok") {
				err = fmt.Errorf("status=%d body=%q", resp.StatusCode, body)
			}
		}
		result <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DNS lookup did not start")
	}

	done := make(chan struct{})
	go func() { shutdownServers(x, s.Config, admin.Config, o); close(done) }()
	t.Cleanup(func() {
		releaseLookup()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("shutdown did not finish")
		}
	})

	// Wait until Shutdown has closed the listener while the lookup is still pending.
	eventually(t, func() bool {
		c, err := net.DialTimeout("tcp", s.Listener.Addr().String(), 50*time.Millisecond)
		if err != nil {
			return true
		}
		_ = c.Close()
		return false
	})
	if x.ctx.Err() != nil {
		t.Fatal("shutdown canceled pending DNS before the grace period expired")
	}
	if status := getStatus(t, admin.URL+"/readyz"); status != 503 {
		t.Fatal(status)
	}
	if status := getStatus(t, admin.URL+"/livez"); status != 200 {
		t.Fatal(status)
	}

	// DNS completes and the upstream TCP dial begins after Shutdown has started.
	releaseLookup()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("in-flight HTTP request failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight HTTP request did not finish")
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not finish")
	}
	if x.ctx.Err() == nil {
		t.Fatal("proxy context was not canceled after draining")
	}
}

func TestShutdownDelayKeepsServingAfterUnready(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()

	o := defaultOptions()
	o.shutdownDelay = 500 * time.Millisecond
	o.shutdownTimeout = time.Second
	x, s, admin := newTestProxyWithAdmin(t, testUpstreamPolicy(t, upstream.Listener.Addr().String()), o)
	done := make(chan struct{})
	start := time.Now()
	go func() { shutdownServers(x, s.Config, admin.Config, o); close(done) }()

	eventually(t, func() bool { return !x.ready.Load() })
	if status := getStatus(t, admin.URL+"/readyz"); status != 503 {
		t.Fatal(status)
	}
	if status := getStatus(t, admin.URL+"/livez"); status != 200 {
		t.Fatal(status)
	}

	proxyURL, _ := url.Parse(s.URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + testUpstreamAddress(t, upstream.Listener.Addr().String()))
	if err != nil {
		t.Fatalf("new connection during propagation delay failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("status=%d body=%q err=%v", resp.StatusCode, body, err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish")
	}
	if time.Since(start) < o.shutdownDelay {
		t.Fatal("shutdown skipped the propagation delay")
	}
}

func TestShutdownTimeoutCancelsRemainingRequests(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); upstream.Close() })

	o := defaultOptions()
	o.shutdownDelay = 0
	o.shutdownTimeout = 100 * time.Millisecond
	x, s, admin := newTestProxyWithAdmin(t, testUpstreamPolicy(t, upstream.Listener.Addr().String()), o)
	proxyURL, _ := url.Parse(s.URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	result := make(chan error, 1)
	go func() {
		resp, err := client.Get("http://" + testUpstreamAddress(t, upstream.Listener.Addr().String()))
		if resp != nil {
			_ = resp.Body.Close()
		}
		result <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not reach upstream")
	}
	start := time.Now()
	shutdownServers(x, s.Config, admin.Config, o)
	if elapsed := time.Since(start); elapsed < o.shutdownTimeout || elapsed > time.Second {
		t.Fatalf("unexpected shutdown duration: %v", elapsed)
	}
	if x.ctx.Err() == nil {
		t.Fatal("remaining proxy work was not canceled")
	}

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("unfinished request unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("request remained open past the shutdown timeout")
	}
}

func TestRequestHeaderLimit(t *testing.T) {
	o := defaultOptions()
	o.maxHeaderBytes = 1024
	_, s, _ := newTestProxyWithAdmin(t, testPolicy(t, "large.example.com:80"), o)

	conn, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Go permits a small read allowance beyond MaxHeaderBytes.
	_, _ = fmt.Fprintf(conn, "GET http://large.example.com/ HTTP/1.1\r\nHost: large.example.com\r\nX-Large: %s\r\n\r\n", strings.Repeat("a", 8192))
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatal(response.Status)
	}
}

func TestUpstreamResponseHeaderLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Large", strings.Repeat("a", 4096))
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	o := defaultOptions()
	o.maxHeaderBytes = 1024
	_, s, _ := newTestProxyWithAdmin(t, testUpstreamPolicy(t, upstream.Listener.Addr().String()), o)
	proxyURL, _ := url.Parse(s.URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}

	response, err := client.Get("http://" + testUpstreamAddress(t, upstream.Listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatal(response.Status)
	}
}

func TestAdminConnectionLimit(t *testing.T) {
	_, _, admin := newTestProxyWithAdmin(t, testPolicy(t), defaultOptions())
	listener := admin.Listener.(*limitedListener)
	var clients []net.Conn
	t.Cleanup(func() {
		for _, c := range clients {
			_ = c.Close()
		}
	})

	for range maxAdminConnections {
		conn, err := net.Dial("tcp", admin.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, conn)
	}
	eventually(t, func() bool { return len(listener.slots) == maxAdminConnections })

	extra, err := net.Dial("tcp", admin.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("admin connection limit was not enforced")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("over-limit admin connection was not closed")
	}

	_ = clients[0].Close()
	eventually(t, func() bool { return len(listener.slots) < maxAdminConnections })
	if status := getStatus(t, admin.URL+"/livez"); status != 200 {
		t.Fatal(status)
	}
}

func TestUpstreamAdmissionLimit(t *testing.T) {
	o := defaultOptions()
	o.maxConnections = 1
	x := newProxy(testPolicy(t, "pending.example.com:443"), "", o)
	defer x.cancel()
	defer x.transport.CloseIdleConnections()

	started := make(chan struct{}, cap(x.upstreamSlots))
	x.lookupIP = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	results := make(chan error, cap(x.upstreamSlots))

	for range cap(x.upstreamSlots) {
		go func() {
			_, err := x.dialUpstream(context.Background(), "tcp", "pending.example.com:443")
			results <- err
		}()
	}
	for range cap(x.upstreamSlots) {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("pending dial did not start")
		}
	}

	if _, err := x.dialUpstream(context.Background(), "tcp", "pending.example.com:443"); !errors.Is(err, errUpstreamLimit) {
		t.Fatalf("unbounded pending dial: %v", err)
	}
	w := httptest.NewRecorder()
	x.writeError(w, errUpstreamLimit, "http")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal(w.Code)
	}

	for _, protocol := range []string{"http", "connect"} {
		_, err := x.dialUpstream(context.Background(), "tcp", "denied.example.com:443")
		if !errors.Is(err, errDenied) {
			t.Fatalf("policy denial hidden by full upstream slots: %v", err)
		}
		w := httptest.NewRecorder()
		x.writeError(w, err, protocol)
		if w.Code != http.StatusForbidden {
			t.Fatalf("denied status: %d", w.Code)
		}
	}
	metrics := httptest.NewRecorder()
	x.adminHandler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, protocol := range []string{"http", "connect"} {
		want := fmt.Sprintf(`monban_denied_total{protocol="%s"} 1`, protocol)
		if !strings.Contains(metrics.Body.String(), want) {
			t.Fatalf("missing denial metric: %s", want)
		}
	}

	x.cancel()
	for range cap(x.upstreamSlots) {
		select {
		case err := <-results:
			if err == nil {
				t.Fatal("canceled dial succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("pending dial was not canceled")
		}
	}
	if len(x.upstreamSlots) != 0 {
		t.Fatal("upstream slots leaked after failed dials")
	}
}

func TestUpstreamSlotReleasedOnClose(t *testing.T) {
	upstream := newTestEchoListener(t)
	x := newProxy(testUpstreamPolicy(t, upstream.Addr().String()), "", defaultOptions())
	defer x.cancel()
	defer x.transport.CloseIdleConnections()
	setTestUpstreamResolver(x)

	conn, err := x.dialUpstream(context.Background(), "tcp", testUpstreamAddress(t, upstream.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(x.upstreamSlots) != 1 {
		t.Fatal("connected upstream was not accounted")
	}
	_ = conn.Close()
	_ = conn.Close()
	if len(x.upstreamSlots) != 0 {
		t.Fatal("closing upstream did not release its slot")
	}
}

// A wrapped connection may support half-close without being a *net.TCPConn.
type halfCloseTestConn struct {
	net.Conn
	called bool
	err    error
}

func (c *halfCloseTestConn) CloseWrite() error {
	c.called = true
	return c.err
}

func TestConnectionWrapperCloseWrite(t *testing.T) {
	for _, wrap := range []struct {
		name string
		conn func(net.Conn) interface{ CloseWrite() error }
	}{
		{"limited", func(c net.Conn) interface{ CloseWrite() error } { return &limitedConn{Conn: c} }},
		{"metered", func(c net.Conn) interface{ CloseWrite() error } { return &meteredConn{Conn: c} }},
	} {
		t.Run(wrap.name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()

			if err := wrap.conn(client).CloseWrite(); err != nil {
				t.Fatalf("connection without half-close: %v", err)
			}

			want := errors.New("half-close failure")
			underlying := &halfCloseTestConn{Conn: client, err: want}
			if err := wrap.conn(underlying).CloseWrite(); !errors.Is(err, want) || !underlying.called {
				t.Fatalf("half-close not forwarded: called=%v err=%v", underlying.called, err)
			}
		})
	}
}
