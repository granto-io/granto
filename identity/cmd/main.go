package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/granto-io/granto/identity/internal/di"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config (empty: defaults + IDENTITY_* env)")
	flag.Parse()

	path := *configPath
	if path == "" {
		path = os.Getenv("IDENTITY_CONFIG")
	}

	a, err := di.InitializeApp(di.ConfigPath(path))
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a.Logger.Info("granto-identity starting",
		"grpc_addr", a.Config.Server.GRPCAddr,
		"rest_addr", a.Config.Server.RESTAddr,
		"shutdown_timeout", a.Config.Server.ShutdownTimeout,
	)

	if err := a.Run(ctx); err != nil {
		a.Logger.Error("granto-identity stopped with error", "error", err)
		os.Exit(1)
	}

	a.Logger.Info("granto-identity stopped gracefully")
}
