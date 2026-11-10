package monban

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	registry    *prometheus.Registry
	connections prometheus.Gauge
	rejected    prometheus.Counter
	requests    *prometheus.CounterVec
	denied      *prometheus.CounterVec
	invalid     *prometheus.CounterVec
	errors      *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	active      prometheus.Gauge
	tunnels     prometheus.Gauge
	bytes       *prometheus.CounterVec
	dns         prometheus.Counter
	dnsDuration prometheus.Histogram
}

func newMetrics() *metrics {
	m := &metrics{
		registry: prometheus.NewRegistry(),
		connections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "monban_connections",
			Help: "Open client connections, including idle connections and tunnels.",
		}),
		rejected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "monban_connections_rejected_total",
			Help: "Connections closed because the connection limit was reached.",
		}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "monban_requests_total",
			Help: "Requests received by the proxy.",
		}, []string{"protocol"}),
		denied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "monban_denied_total",
			Help: "Requests rejected by destination policy.",
		}, []string{"protocol"}),
		invalid: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "monban_invalid_total",
			Help: "Invalid proxy requests.",
		}, []string{"protocol"}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "monban_errors_total",
			Help: "Failures by stage. One request may fail at multiple stages.",
		}, []string{"stage"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "monban_request_duration_seconds",
			Help:    "Request duration, including tunnel lifetime for CONNECT.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 300, 1800, 3600},
		}, []string{"protocol"}),
		active: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "monban_active_requests",
			Help: "Requests currently being handled, including tunnels.",
		}),
		tunnels: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "monban_tunnels",
			Help: "Established CONNECT tunnels.",
		}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "monban_upstream_bytes_total",
			Help: "TCP bytes transferred to and from upstreams, including HTTP headers.",
		}, []string{"direction"}),
		dns: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "monban_dns_lookups_total",
			Help: "Hostname lookups initiated. Literal IP requests are excluded.",
		}),
		dnsDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "monban_dns_lookup_duration_seconds",
			Help: "Hostname lookup duration.",
		}),
	}

	m.registry.MustRegister(
		m.connections,
		m.rejected,
		m.requests,
		m.denied,
		m.invalid,
		m.errors,
		m.duration,
		m.active,
		m.tunnels,
		m.bytes,
		m.dns,
		m.dnsDuration,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// Create only fixed label values, never destination or client labels.
	for _, protocol := range []string{"http", "connect"} {
		m.requests.WithLabelValues(protocol)
		m.denied.WithLabelValues(protocol)
		m.invalid.WithLabelValues(protocol)
		m.duration.WithLabelValues(protocol)
	}

	for _, stage := range []string{"dns", "dial", "connect", "http", "tunnel"} {
		m.errors.WithLabelValues(stage)
	}

	for _, direction := range []string{"sent", "received"} {
		m.bytes.WithLabelValues(direction)
	}

	return m
}

func (p *proxy) adminHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !p.ready.Load() || len(p.slots) == cap(p.slots) {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}

		_, _ = w.Write([]byte("ok\n"))
	})

	mux.Handle("GET /metrics", promhttp.HandlerFor(p.metrics.registry, promhttp.HandlerOpts{
		MaxRequestsInFlight: 2,
		Timeout:             5 * time.Second,
	}))

	return mux
}
