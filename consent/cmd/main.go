package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/granto-io/granto/consent/pkg/server"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config (empty: defaults + CONSENT_* env)")
	flag.Parse()

	path := *configPath
	if path == "" {
		path = os.Getenv("CONSENT_CONFIG")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, path); err != nil {
		fmt.Fprintf(os.Stderr, "consent stopped with error: %v\n", err)
		os.Exit(1)
	}
}
