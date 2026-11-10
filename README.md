# monban

monban is a small egress proxy for Kubernetes. Applications send HTTP and HTTPS
traffic through it, and monban only connects to destinations you allow by FQDN.

- FQDN allowlist with exact, `*.` and `**.` rules
- Resolved IPs are checked against built-in private and special-purpose ranges
- Connection limits, timeouts, health checks, and Prometheus metrics
- Single binary written in Go

> **Status:** 0.1.0, early release. The interface may change, and the project has
> not been independently audited.

monban is meant to be used together with NetworkPolicy, which limits who can
reach the proxy and blocks direct egress from applications.

## Quick start

```sh
docker run --rm -p 127.0.0.1:8888:8888 ghcr.io/soora-jp/monban \
  --allow api.wordpress.org:443

curl -x http://127.0.0.1:8888 https://api.wordpress.org/   # allowed
curl -x http://127.0.0.1:8888 https://example.com/         # 403
```

Point applications at the proxy with `HTTP_PROXY` and `HTTPS_PROXY`.

## How it works

1. The requested FQDN and port must match an `--allow` rule. Literal IPs are
   always denied.
2. monban resolves the FQDN. If any resolved address is in a banned range, the
   request is denied.
3. monban connects to the checked address and forwards HTTP, or tunnels the TCP
   stream for `CONNECT`.

See [how it works](docs/how-it-works.md) for details.

## Documentation

- [Configuration](docs/configuration.md): flags, allow rules, IP bans, pinholes
- [How it works](docs/how-it-works.md): request flow, protocols, limits, shutdown
- [Kubernetes](docs/kubernetes.md): example deployment and NetworkPolicy
- [Operations](docs/operations.md): health checks, logs, metrics, sizing
- [Security model](docs/security-model.md): what monban does and does not protect
- [Development](docs/development.md): build, test, pull requests
- [Release](docs/release.md): branches, CI, release steps

## Security

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). The container image also includes the licenses of Go and the
bundled third-party modules under `/licenses`.
