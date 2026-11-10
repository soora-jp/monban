package monban

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const maxAdminConnections = 16

// Run parses command-line flags and runs the proxy until interrupted.
func Run(args []string) error {
	c, err := parseConfig(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}

	if errors.Is(err, errVersion) {
		fmt.Println(version)
		return nil
	}

	if err != nil {
		return err
	}

	var level slog.Level
	_ = level.UnmarshalText([]byte(c.logLevel)) // Validated by parseConfig.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-signalCtx.Done()
		// Restore default signal handling before starting graceful shutdown.
		stop()
		cancel()
	}()

	return serve(ctx, c.listen, c.adminListen, c.policy, c.dnsServer, c.options)
}

func serve(ctx context.Context, listen, adminListen string, p policy, dnsServer string, o options) error {
	proxy := newProxy(p, dnsServer, o)
	defer proxy.cancel()
	defer proxy.transport.CloseIdleConnections()

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}

	defer listener.Close()

	adminListener, err := net.Listen("tcp", adminListen)
	if err != nil {
		return err
	}

	defer adminListener.Close()

	srv := &http.Server{
		Handler:           proxy,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
		ReadHeaderTimeout: o.headerTimeout,
		IdleTimeout:       o.idleTimeout,
		MaxHeaderBytes:    o.maxHeaderBytes,
	}

	admin := &http.Server{
		Handler:           proxy.adminHandler(),
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	serveErrors := make(chan error, 2)
	proxy.ready.Store(true)
	go func() {
		serveErrors <- srv.Serve(&limitedListener{Listener: listener, slots: proxy.slots, metrics: proxy.metrics, bufferSize: o.tcpBufferSize})
	}()

	go func() {
		serveErrors <- admin.Serve(&limitedListener{
			Listener:   adminListener,
			slots:      make(chan struct{}, maxAdminConnections),
			bufferSize: o.tcpBufferSize,
		})
	}()

	slog.Info("proxy listening", "proxy", listener.Addr().String(), "admin", adminListener.Addr().String())

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-serveErrors:
	}

	if serveErr != nil {
		// A failed listener cannot accept traffic during endpoint propagation.
		o.shutdownDelay = 0
	}
	shutdownServers(proxy, srv, admin, o)

	return serveErr
}

func shutdownServers(proxy *proxy, srv, admin *http.Server, o options) {
	proxy.ready.Store(false)

	// Continue accepting traffic until endpoint removal has had time to propagate.
	time.Sleep(o.shutdownDelay)

	shutdown, cancel := context.WithTimeout(context.Background(), o.shutdownTimeout)
	defer cancel()

	// Keep upstream dialing alive until HTTP requests finish or the grace expires.
	// Admin stays available and reports not ready throughout this period.
	if err := srv.Shutdown(shutdown); err != nil {
		_ = srv.Close()
	}

	proxy.cancel()
	_ = admin.Close()
}
