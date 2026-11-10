# Security policy

## Reporting a vulnerability

Do not open a public issue. Report privately through GitHub:
<https://github.com/soora-jp/monban/security/advisories/new>

Please include:

- the monban version or commit
- the relevant configuration, with secrets removed
- steps to reproduce and the expected impact

## Supported versions

Only the latest release receives security fixes.

## Scope

[docs/security-model.md](docs/security-model.md) lists the limitations that are
part of the design, such as no TLS inspection and no authentication. Reports
about those are welcome as feature requests, but are not treated as
vulnerabilities.
