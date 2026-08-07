package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/granto-io/granto/core/internal/di"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config (empty: defaults + GRANTO_* env)")
	flag.Parse()

	path := *configPath
	if path == "" {
		path = os.Getenv("GRANTO_CONFIG")
	}

	a, err := di.InitializeApp(di.ConfigPath(path))
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a.Logger.Info("granto-core starting",
		"public_addr", a.Config.Server.PublicAddr,
		"admin_rest_addr", a.Config.Server.AdminRESTAddr,
		"admin_grpc_addr", a.Config.Server.AdminGRPCAddr,
		"shutdown_timeout", a.Config.Server.ShutdownTimeout,
	)

	if err := a.Run(ctx); err != nil {
		a.Logger.Error("granto-core stopped with error", "error", err)
		os.Exit(1)
	}

	a.Logger.Info("granto-core stopped gracefully")
}
