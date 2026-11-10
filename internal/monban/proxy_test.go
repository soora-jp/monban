package monban

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func newTestProxyServer(t *testing.T, p policy) *httptest.Server {
	t.Helper()

	x := newProxy(p, "127.0.0.1:1", defaultOptions())
	setTestUpstreamResolver(x)
	s := httptest.NewServer(x)
	t.Cleanup(func() {
		x.cancel()
		x.transport.CloseIdleConnections()
		s.Close()
	})

	return s
}

func TestHTTPProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Remove") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("hop headers forwarded")
		}

		w.Header().Set("Connection", "X-Secret")
		w.Header().Set("X-Secret", "hidden")
		_, _ = io.WriteString(w, "hello")
	}))
	defer upstream.Close()

	target := testUpstreamAddress(t, upstream.Listener.Addr().String())
	for _, allowed := range []bool{false, true} {
		t.Run(fmt.Sprint(allowed), func(t *testing.T) {
			p := testPolicy(t)
			if allowed {
				p = testUpstreamPolicy(t, upstream.Listener.Addr().String())
			}

			s := newTestProxyServer(t, p)
			u, _ := url.Parse(s.URL)
			tr := &http.Transport{Proxy: http.ProxyURL(u)}
			defer tr.CloseIdleConnections()

			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			req, _ := http.NewRequest("GET", "http://"+target, nil)
			req.Header.Set("Connection", "X-Remove")
			req.Header.Set("X-Remove", "secret")
			req.Header.Set("Proxy-Authorization", "secret")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}

			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			if allowed {
				if resp.StatusCode != 200 || string(body) != "hello" || resp.Header.Get("X-Secret") != "" {
					t.Fatalf("response %d %s", resp.StatusCode, body)
				}
			} else if resp.StatusCode != 403 {
				t.Fatal(resp.Status)
			}
		})
	}
}

func TestHTTPSConnect(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "encrypted") }))
	defer upstream.Close()

	target := testUpstreamAddress(t, upstream.Listener.Addr().String())
	s := newTestProxyServer(t, testUpstreamPolicy(t, upstream.Listener.Addr().String()))
	u, _ := url.Parse(s.URL)
	tr := &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + target)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "encrypted" {
		t.Fatal(string(body))
	}
}

func TestConnectBufferedData(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer l.Close()

	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}

		defer c.Close()

		b := make([]byte, 4)
		if _, err = io.ReadFull(c, b); err == nil {
			_, _ = c.Write(b)
		}
	}()

	s := newTestProxyServer(t, testUpstreamPolicy(t, l.Addr().String()))
	c, err := net.Dial("tcp", strings.TrimPrefix(s.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nping", testUpstreamAddress(t, l.Addr().String()), testUpstreamAddress(t, l.Addr().String()))
	reader := bufio.NewReader(c)
	req := &http.Request{Method: "CONNECT"}
	resp, err := http.ReadResponse(reader, req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}

	b := make([]byte, 4)
	if _, err = io.ReadFull(reader, b); err != nil || string(b) != "ping" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestRequestRejections(t *testing.T) {
	p := testPolicy(t)
	x := newProxy(p, "127.0.0.1:1", defaultOptions())
	defer x.transport.CloseIdleConnections()

	for _, tc := range []struct {
		method, target string
		status         int
	}{
		{"GET", "http://secret.example.com/", 403},
		{"GET", "/relative", 400},
		{"GET", "https://example.com/", 400},
		{"CONNECT", "secret.example.com:443", 403},
		{"CONNECT", "secret.example.com", 400},
	} {
		req := httptest.NewRequest(tc.method, tc.target, nil)
		w := httptest.NewRecorder()
		x.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Errorf("%s %s: got %d want %d", tc.method, tc.target, w.Code, tc.status)
		}
	}
}

func TestConnectShutdown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()

	p := testUpstreamPolicy(t, upstream.Listener.Addr().String())
	x := newProxy(p, "", defaultOptions())
	setTestUpstreamResolver(x)
	s := httptest.NewServer(x)
	defer s.Close()
	defer x.cancel()
	defer x.transport.CloseIdleConnections()

	c, err := net.Dial("tcp", strings.TrimPrefix(s.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", testUpstreamAddress(t, upstream.Listener.Addr().String()), testUpstreamAddress(t, upstream.Listener.Addr().String()))
	reader := bufio.NewReader(c)
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("%v %v", response, err)
	}

	x.cancel()
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("expected closed tunnel, got %v", err)
	}
}

func testUpstreamAddress(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	return net.JoinHostPort("upstream.test", port)
}

func testUpstreamPolicy(t *testing.T, addr string) policy {
	t.Helper()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	ip := netip.MustParseAddr(host)
	p := testPolicy(t, testUpstreamAddress(t, addr))
	p.pinholes = []pinhole{{host: "upstream.test", prefix: netip.PrefixFrom(ip, ip.BitLen())}}
	return p
}

func setTestUpstreamResolver(p *proxy) {
	p.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		if len(p.policy.pinholes) == 0 {
			return nil, fmt.Errorf("test upstream is not configured")
		}

		return []netip.Addr{p.policy.pinholes[0].prefix.Addr()}, nil
	}
}

func TestBannedIPAndPinholeHTTPAndConnect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()

	for _, pinhole := range []bool{false, true} {
		t.Run(fmt.Sprintf("pinhole=%t", pinhole), func(t *testing.T) {
			p := testUpstreamPolicy(t, upstream.Listener.Addr().String())
			resolvedIP := p.pinholes[0].prefix.Addr()
			if !pinhole {
				p.pinholes = nil
			}

			x := newProxy(p, "", defaultOptions())
			x.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) { return []netip.Addr{resolvedIP}, nil }
			s := httptest.NewServer(x)
			defer s.Close()
			defer x.cancel()
			defer x.transport.CloseIdleConnections()

			for _, method := range []string{"GET", "CONNECT"} {
				for _, literalIP := range []bool{false, true} {
					target := testUpstreamAddress(t, upstream.Listener.Addr().String())
					if literalIP {
						target = upstream.Listener.Addr().String()
					}

					requestTarget := target
					if method == "GET" {
						requestTarget = "http://" + target + "/"
					}

					c, err := net.Dial("tcp", s.Listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}

					_ = c.SetDeadline(time.Now().Add(2 * time.Second))
					_, _ = fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, requestTarget, target)
					resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
					if err != nil {
						_ = c.Close()
						t.Fatal(err)
					}

					want := 403
					if pinhole && !literalIP {
						want = 200
					}

					if resp.StatusCode != want {
						t.Errorf("%s %s: status=%d want %d", method, target, resp.StatusCode, want)
					}

					if method == "GET" && want == 200 {
						body, err := io.ReadAll(resp.Body)
						if err != nil || string(body) != "ok" {
							t.Errorf("body=%q err=%v", body, err)
						}
					}

					_ = c.Close()
					_ = resp.Body.Close()
				}
			}
		})
	}
}

func TestConnectHalfClose(t *testing.T) {
	for _, first := range []string{"upstream", "client"} {
		t.Run(first+" EOF first", func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			payload := strings.Repeat("upload continues after EOF\n", 128)
			result := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					result <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

				tcp := conn.(*net.TCPConn)
				if first == "upstream" {
					if _, err = io.WriteString(tcp, "ready"); err == nil {
						err = tcp.CloseWrite()
					}
					if err != nil {
						result <- err
						return
					}
				}

				body, err := io.ReadAll(tcp)
				if err == nil && string(body) != payload {
					err = fmt.Errorf("upload truncated: got %d bytes, want %d", len(body), len(payload))
				}
				if err == nil && first == "client" {
					if _, err = io.WriteString(tcp, "received"); err == nil {
						err = tcp.CloseWrite()
					}
				}
				result <- err
			}()

			// Use the admission-controlled listener to exercise limitedConn.CloseWrite.
			_, server, _ := newTestProxyWithAdmin(t, testUpstreamPolicy(t, listener.Addr().String()), defaultOptions())
			conn, reader := openTunnel(t, server, testUpstreamAddress(t, listener.Addr().String()))
			tcp := conn.(*net.TCPConn)

			if first == "upstream" {
				body, err := io.ReadAll(reader)
				if err != nil || string(body) != "ready" {
					t.Fatalf("upstream EOF: body=%q err=%v", body, err)
				}
			}

			if _, err := io.WriteString(tcp, payload); err != nil {
				t.Fatal(err)
			}
			if err := tcp.CloseWrite(); err != nil {
				t.Fatal(err)
			}

			if first == "client" {
				body, err := io.ReadAll(reader)
				if err != nil || string(body) != "received" {
					t.Fatalf("response after client EOF: body=%q err=%v", body, err)
				}
			}

			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("half-closed tunnel did not finish")
			}
		})
	}
}

func testTunnelErrorCount(t *testing.T, p *proxy) float64 {
	t.Helper()

	families, err := p.metrics.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "monban_errors_total" {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "stage" && label.GetValue() == "tunnel" {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	t.Fatal("missing tunnel error counter")
	return 0
}

func TestTunnelErrorClassification(t *testing.T) {
	reset := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	for _, tc := range []struct {
		name     string
		err      error
		shutdown bool
		want     float64
	}{
		{name: "EOF", err: io.EOF},
		{name: "successful copy"},
		{name: "local close", err: fmt.Errorf("copy failed: %w", net.ErrClosed)},
		{name: "idle timeout", err: &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}},
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "canceled", err: context.Canceled},
		{name: "shutdown", err: reset, shutdown: true},
		{name: "peer reset", err: reset, want: 1},
		{name: "broken pipe", err: &net.OpError{Op: "write", Net: "tcp", Err: syscall.EPIPE}, want: 1},
		{name: "truncated data", err: io.ErrUnexpectedEOF, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newProxy(testPolicy(t), "", defaultOptions())
			defer p.cancel()
			defer p.transport.CloseIdleConnections()

			if tc.shutdown {
				p.cancel()
			}
			p.recordTunnelError(tc.err)
			if got := testTunnelErrorCount(t, p); got != tc.want {
				t.Fatalf("tunnel errors=%v want %v", got, tc.want)
			}
		})
	}
}

func TestPolicyDenialLogs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ip     string
		http   bool
		reason string
	}{
		{name: "HTTP allowlist", http: true, reason: "allowlist"},
		{name: "CONNECT allowlist", reason: "allowlist"},
		{name: "banned IP", ip: "10.1.2.3", reason: "banned_ip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer slog.SetDefault(previous)

			p := newProxy(testPolicy(t), "", defaultOptions())
			defer p.cancel()
			defer p.transport.CloseIdleConnections()
			if tc.http {
				w := httptest.NewRecorder()
				p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://internal.example.com/private?secret=value", nil))
				if w.Code != http.StatusForbidden {
					t.Fatal(w.Code)
				}
			} else {
				if tc.ip != "" {
					p.policy = testPolicy(t, "internal.example.com:80")
					p.lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
						return []netip.Addr{netip.MustParseAddr(tc.ip)}, nil
					}
				}
				if _, err := p.dialUpstream(context.Background(), "tcp", "internal.example.com:80"); !errors.Is(err, errDenied) {
					t.Fatal(err)
				}
			}
			var entry map[string]any
			if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
				t.Fatalf("invalid or duplicate log: %v: %s", err, output.String())
			}
			if entry["level"] != "DEBUG" || entry["host"] != "internal.example.com" || entry["port"] != "80" || entry["reason"] != tc.reason {
				t.Fatalf("unexpected log: %v", entry)
			}
			if tc.ip != "" && entry["ip"] != tc.ip {
				t.Fatalf("missing banned IP: %v", entry)
			}
			if strings.Contains(output.String(), "secret") {
				t.Fatal("query leaked into log")
			}
		})
	}
}
