# Security model

monban limits **where** applications can connect. It does not inspect **what**
they send.

## What monban enforces

- Only allowlisted FQDN and port pairs are reachable. Literal IPs are rejected.
- FQDNs that resolve into private, loopback, link-local, metadata, or other
  special ranges are rejected, unless a pinhole explicitly allows them.
- Checked IPs are dialed directly, so DNS rebinding between the check and the
  connection is not possible.
- Connection, header, and timeout limits stop a single client from exhausting
  the proxy.

## What monban does not do

- **No authentication.** Every client that can reach the port shares the same
  allowlist. Network access to the proxy is the only access control.
- **No TLS inspection.** CONNECT is checked by its requested FQDN only. A client
  can send a different SNI or any TCP protocol to an allowed server, for example
  through a CDN that hosts many sites.
- **No content filtering.** Allowed destinations can receive any data.
- **No DNS filtering for wildcards.** `*.example.com` lets clients put arbitrary
  labels in DNS queries, which can carry data out through DNS.
- **No rechecking.** Keep-alive connections and tunnels keep their original IP
  even if DNS changes.
- **No per-application policy.** All clients share one configuration.

## Deployment requirements

- Never expose the proxy or admin port to the internet.
- Enforce egress with NetworkPolicy or a firewall, and verify it on your network.
  See [Kubernetes](kubernetes.md#check-the-boundary).
- Ban any public ranges that belong to your internal services with
  `--add-ban-ip`.
- Keep pinholes and wildcards as narrow as possible.

Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).
