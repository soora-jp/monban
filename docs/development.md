# Development

Requires Go 1.27.

```sh
go build -o bin/monban ./cmd/monban
go test -race ./...
go vet ./...
```

## Memory check

`scripts/memory-check.py` runs monban in a temporary 128Mi cgroup and checks
that it survives heavy load without an OOM kill. It requires Linux with cgroup v2,
a user systemd session, and Python 3. Build the binary first:

```sh
go build -o bin/monban ./cmd/monban
python3 scripts/memory-check.py [result.json]
```

Run it after changing buffers, limits, or connection handling.

## Pull requests

Branch from `develop` and open pull requests against `develop`. CI must pass.

## Version

`--version` prints the version embedded at build time, or `dev` if none was set:

```sh
go build -ldflags '-X github.com/soora-jp/monban/internal/monban.version=0.1.0' -o bin/monban ./cmd/monban
docker build --build-arg VERSION=0.1.0 .
```

## Container image

The image bundles license files for Go and every linked module under
`/licenses`. The build fails if a module has no license file.

Images are published by the release workflow. See [release](release.md).
