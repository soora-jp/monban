package monban

import "errors"

// version is set at build time:
//
//	go build -ldflags '-X github.com/soora-jp/monban/internal/monban.version=0.1.0' ./cmd/monban
var version = "dev"

// errVersion asks Run to print the version instead of starting the proxy.
var errVersion = errors.New("version requested")
