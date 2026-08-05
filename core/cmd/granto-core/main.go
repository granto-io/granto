package main

import (
	"fmt"
	"os"

	"github.com/granto-io/granto/core/internal/di"
)

func main() {
	a, err := di.InitializeApp()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		os.Exit(1)
	}

	a.Logger.Info("granto-core initialized",
		"public_handler", a.Public != nil,
	)
}
