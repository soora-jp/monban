# How it works

## Request flow

1. **Parse.** HTTP requests need an absolute `http://` URL (default port 80).
   HTTPS uses `CONNECT host:port`.
2. **Allowlist.** The FQDN and port must match an `--allow` rule. Otherwise
   monban returns 403 without a DNS lookup.
3. **Resolve.** monban looks up the FQDN over TCP with a trailing dot, so search
   domains are never tried. Any lookup error or empty answer fails the request.
4. **Check IPs.** Every resolved address must pass the IP bans or match a pinhole.
   One banned address denies the request.
5. **Connect.** monban connects to the checked addresses in order, without
   another lookup. Each attempt is capped at 10 seconds, and the whole step at
   `--connect-timeout`.

Existing keep-alive connections and tunnels are not rechecked.

## HTTP

- monban forwards the request to the checked destination and sets the `Host`
  header to match it.
- It removes hop-by-hop headers and `Proxy-Authorization`, and adds no
  `X-Forwarded-*` headers.
- Redirects go back to the client. Each new request is checked again.
- `Upgrade` requests (such as WebSocket over plain HTTP) are rejected.

## CONNECT

- After the checks, monban returns `200 Connection Established` and copies bytes
  in both directions.
- It does not inspect TLS: there is no SNI or certificate check. Any TCP protocol
  can run inside an allowed tunnel.
- When one side finishes sending, monban closes only that direction. The other
  direction stays open until it finishes too.

## Not supported

Authentication, transparent proxying, HTTP/2 to the proxy, and TLS interception.

## Status codes

| Status | Reason |
|---|---|
| 400 | Invalid request, such as a relative URL or bad `CONNECT` target |
| 403 | Denied by the allowlist or IP bans |
| 431 | Request headers larger than `--max-header-bytes` |
| 502 | DNS, connection, or upstream failure |
| 503 | Upstream connection budget exhausted |

A timeout after the response has started closes the connection instead of
returning a status.

## Limits and timeouts

- **Client connections.** At `--max-connections`, new connections are closed
  immediately. Idle keep-alive connections and tunnels count toward the limit.
- **Upstream connections.** At most twice `--max-connections` upstream sockets,
  including pending dials and idle pooled connections. Beyond that, monban
  returns 503.
- **Headers.** Request and upstream response headers are capped at
  `--max-header-bytes`.
- **HTTP.** `--header-timeout` covers request headers and the wait for upstream
  response headers. `--request-timeout` covers the whole exchange, including
  bodies. Long streaming responses need a larger value.
- **Tunnels.** A tunnel closes after `--idle-timeout` without traffic, or after
  `--tunnel-timeout` in total.

## Shutdown

On `SIGTERM` or `SIGINT`:

1. `/readyz` returns 503. The proxy keeps accepting connections for
   `--shutdown-delay`, so load balancers can remove the endpoint first.
2. The listener closes. In-flight HTTP requests get up to `--shutdown-timeout`
   to finish, and they can still resolve and connect during this time.
3. Remaining connections and tunnels are closed, and the process exits.

Tunnels do not extend step 2. A second signal stops the process immediately.
