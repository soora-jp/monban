# Configuration

## Flags

Every flag has an environment variable: add `MONBAN_`, use uppercase, and replace
`-` with `_` (`--max-connections` → `MONBAN_MAX_CONNECTIONS`).

| Flag | Default | Description |
|---|---|---|
| `--allow FQDN:PORT` | none | Allowed destination. Repeatable. |
| `--add-ban-ip IP/CIDR` | none | Extra banned range, added to the built-in list. Repeatable. |
| `--pinhole FQDN=IP/CIDR` | none | Exempt a range from IP bans for one exact FQDN. Repeatable. |
| `--version` | | Print the version and exit. No environment variable. |
| `--log-level` | `info` | `debug`, `info`, `warn`, or `error` |
| `--listen` | `0.0.0.0:8888` | Proxy address |
| `--admin-listen` | `0.0.0.0:9090` | Health and metrics address |
| `--dns-server IP:PORT` | system resolver | DNS server to use instead of the system configuration |
| `--max-connections` | `32` | Open client connections, including idle ones and tunnels |
| `--tcp-buffer-size` | `262144` | TCP send and receive buffer per socket, in bytes. `0` uses OS defaults. |
| `--max-header-bytes` | `16384` | Request and upstream response header limit |
| `--connect-timeout` | `10s` | DNS lookup plus upstream connection |
| `--dns-timeout` | `5s` | DNS lookup |
| `--header-timeout` | `10s` | Reading request headers and waiting for upstream response headers |
| `--request-timeout` | `5m` | Whole HTTP request, including bodies |
| `--idle-timeout` | `60s` | Idle keep-alive connections and inactive tunnels |
| `--tunnel-timeout` | `1h` | Maximum tunnel lifetime. `0` disables it. |
| `--shutdown-delay` | `5s` | Time to keep serving after becoming unready. `0` disables it. |
| `--shutdown-timeout` | `10s` | Time for in-flight HTTP requests to finish on shutdown |

Precedence is **CLI flag > environment variable > default**.

- `MONBAN_ALLOW`, `MONBAN_ADD_BAN_IP`, and `MONBAN_PINHOLE` take comma-separated
  lists. Using the flag on the command line replaces the whole list.
- Empty environment variables are ignored.
- Invalid values stop monban at startup. Changes require a restart.

## Allow rules

Everything is denied unless it matches a rule. Rules need an FQDN
(at least one dot) and an exact port.

| Rule | Matches | Does not match |
|---|---|---|
| `example.com:443` | `example.com` | `www.example.com` |
| `*.example.com:443` | `api.example.com` | `example.com`, `a.b.example.com` |
| `**.example.com:443` | `api.example.com`, `a.b.example.com` | `example.com` |

- FQDNs are case-insensitive, and a trailing dot is ignored. Use Punycode for
  internationalized domain names.
- IP addresses, single-label hostnames such as `localhost`, port ranges, and partial wildcards such as
  `api*.example.com` are rejected.
- Requests to literal IPs are always denied.
- Quote wildcard rules in a shell: `--allow '*.example.com:443'`.

## IP bans

After DNS resolution, every returned address must pass the ban list. If any
address is banned, the whole request is denied with 403.

The built-in list cannot be removed or replaced.

| IPv4 | Purpose |
|---|---|
| `0.0.0.0/8` | This network |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Private |
| `100.64.0.0/10` | Shared address space (CGNAT) |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local, including cloud metadata |
| `192.0.0.0/24` | Protocol assignments |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Documentation |
| `198.18.0.0/15` | Benchmarking |
| `224.0.0.0/4` | Multicast |
| `240.0.0.0/4` | Reserved and broadcast |

| IPv6 | Purpose |
|---|---|
| `::/96` | Unspecified, loopback, IPv4-compatible |
| `64:ff9b::/96`, `64:ff9b:1::/48` | IPv4/IPv6 translation |
| `100::/64` | Discard |
| `2001::/32` | Teredo |
| `2001:2::/48` | Benchmarking |
| `2001:db8::/32`, `3fff::/20` | Documentation |
| `2002::/16` | 6to4 |
| `fc00::/7` | Unique local |
| `fe80::/10` | Link-local |
| `fec0::/10` | Site-local (deprecated) |
| `ff00::/8` | Multicast |

IPv4-mapped IPv6 addresses are checked as IPv4. Add your own ranges, such as a
public range used by internal services, with `--add-ban-ip`:

```sh
monban --allow api.example.com:443 --add-ban-ip 203.0.113.10 --add-ban-ip 198.51.100.0/24
```

IP bans apply to proxy destinations only, not to the DNS server.

## Pinholes

A pinhole lets one exact FQDN reach a banned range, for example a cloud service
endpoint with a private IP:

```sh
monban \
  --allow sqs.ap-northeast-1.amazonaws.com:443 \
  --pinhole sqs.ap-northeast-1.amazonaws.com=10.1.0.0/16
```

- The FQDN must still match an `--allow` rule. A pinhole only lifts IP bans.
- The pinhole covers built-in and added bans, for every allowed port of that FQDN.
- It applies only to the requested FQDN. Other FQDNs, wildcards, and CNAME
  targets that resolve into the same range stay banned.
- Use the narrowest range you can. A pinhole opens a path into that network.
