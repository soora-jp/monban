# Operations

## Admin endpoints

Served on `--admin-listen` (default `:9090`), separately from the proxy port.
They have no authentication, so keep this port private.

| Endpoint | Returns |
|---|---|
| `/livez` | 200 while the process is running |
| `/readyz` | 200 when ready. 503 during shutdown or at the connection limit. |
| `/metrics` | Prometheus metrics |

The probes never contact DNS or upstream servers, so an upstream outage does not
cause restarts. The admin server accepts at most 16 connections.

## Logs

monban writes JSON lines to stderr. Set the threshold with `--log-level`.

| Level | Message | Fields |
|---|---|---|
| info | `proxy listening` | `proxy`, `admin` |
| error | `upstream error` | `protocol`, `error` |
| debug | `destination denied` | `host`, `port`, `reason` (`allowlist` or `banned_ip`), `ip` for IP bans |
| debug | `upstream connected` | `host`, `port`, `ip` |

URL paths, query strings, headers, and bodies are never logged.

To find out why an allowed FQDN returns 403, run with `--log-level debug` and look
for `reason: banned_ip`. The FQDN resolved to a banned range; use a pinhole if
that is intended.

## Metrics

No metric uses a destination or client address as a label.

| Metric | Description |
|---|---|
| `monban_connections` | Open client connections |
| `monban_connections_rejected_total` | Connections closed at the limit |
| `monban_requests_total{protocol}` | Requests (`http`, `connect`) |
| `monban_denied_total{protocol}` | Policy denials |
| `monban_invalid_total{protocol}` | Invalid requests |
| `monban_errors_total{stage}` | Failures by `dns`, `dial`, `http`, `connect`, `tunnel` |
| `monban_active_requests` | Requests and tunnels in progress |
| `monban_tunnels` | Open tunnels |
| `monban_request_duration_seconds{protocol}` | Request duration, including tunnel lifetime |
| `monban_upstream_bytes_total{direction}` | Bytes `sent` to and `received` from upstreams |
| `monban_dns_lookups_total` | DNS lookups |
| `monban_dns_lookup_duration_seconds` | DNS lookup duration |

Standard `go_*` and `process_*` metrics are also exported.

One failed request can increment several error stages, for example `dns` and
`connect`. Normal closes, idle timeouts, and shutdown are not counted as tunnel
errors.

Useful queries:

```promql
sum(rate(monban_denied_total[5m])) by (protocol)
sum(rate(monban_connections_rejected_total[5m]))
sum(rate(monban_errors_total[5m])) by (stage)
```

## Sizing

### Memory

Most memory goes to two places:

- **Go heap:** headers, copy buffers, and goroutines. `GOMEMLIMIT` limits it.
- **Kernel TCP queues:** these grow when one side of a connection reads slowly.
  They count toward the container limit, but `GOMEMLIMIT` does not limit them.

With one direction stalled, a tunnel can hold about 4 × `--tcp-buffer-size` in
kernel queues. Set `GOMEMLIMIT` below the container limit by at least
`--max-connections` × 4 × `--tcp-buffer-size`, plus a margin.

The defaults are tuned for a 128Mi container with `GOMEMLIMIT=64MiB`. Measured
on Linux/amd64 with `scripts/memory-check.py`:

| Load (32 connections) | Peak memory |
|---|---|
| Incomplete requests with 14KiB headers | 16MiB |
| Streaming HTTP with 14KiB request and response headers | 26MiB |
| Tunnels transferring in both directions | 35MiB |
| Tunnels whose clients stopped reading | 61MiB |

Measure again if you raise `--max-connections`, `--tcp-buffer-size`, or
`--max-header-bytes`.

### Bandwidth

Per-connection throughput is roughly `--tcp-buffer-size` / round-trip time. The
default 256KiB gives about 25MB/s at 10ms and 2.5MB/s at 100ms.

Linux caps the buffer at `net.core.rmem_max` and `net.core.wmem_max`, which is
often 208KiB. Larger values only take effect if those node settings are raised
as well.
