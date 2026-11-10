package monban

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TCP buffer sizes are requests to the OS; kernel accounting may use more memory.
func setTCPBuffers(conn net.Conn, size int) error {
	tcp, ok := conn.(*net.TCPConn)
	if !ok || size == 0 {
		return nil
	}
	if err := tcp.SetReadBuffer(size); err != nil {
		return err
	}
	return tcp.SetWriteBuffer(size)
}

func dialTCP(ctx context.Context, addr string, bufferSize int) (net.Conn, error) {
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := setTCPBuffers(conn, bufferSize); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Limit accepted sockets, including idle HTTP connections and hijacked tunnels.
type limitedListener struct {
	net.Listener
	slots      chan struct{}
	metrics    *metrics
	bufferSize int
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		select {
		case l.slots <- struct{}{}:
			if err := setTCPBuffers(c, l.bufferSize); err != nil {
				<-l.slots
				if l.metrics != nil {
					l.metrics.rejected.Inc()
				}
				_ = c.Close()
				continue
			}
			if l.metrics != nil {
				l.metrics.connections.Inc()
			}
			return &limitedConn{Conn: c, release: func() {
				<-l.slots
				if l.metrics != nil {
					l.metrics.connections.Dec()
				}
			}}, nil
		default:
			if l.metrics != nil {
				l.metrics.rejected.Inc()
			}
			_ = c.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// Preserve TCP half-close through the client admission-control wrapper.
func (c *limitedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

// Each successful read or write extends the shared tunnel inactivity deadline.
type idleTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleTimeoutConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		_ = c.Conn.SetDeadline(time.Now().Add(c.timeout))
	}

	return n, err
}

func (c *idleTimeoutConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		_ = c.Conn.SetDeadline(time.Now().Add(c.timeout))
	}

	return n, err
}

type meteredConn struct {
	net.Conn
	sent, received prometheus.Counter
	release        func()
}

func (c *meteredConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.received.Add(float64(n))
	return n, err
}

func (c *meteredConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.sent.Add(float64(n))
	return n, err
}

func (c *meteredConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

func (c *meteredConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

// Preserve bytes already read past the CONNECT headers by net/http.
type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
