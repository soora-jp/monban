package main

import (
	"log/slog"
	"os"

	"github.com/soora-jp/monban/internal/monban"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	if err := monban.Run(os.Args[1:]); err != nil {
		slog.Error("monban stopped", "error", err)
		os.Exit(1)
	}
}
