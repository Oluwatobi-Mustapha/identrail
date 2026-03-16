package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
	"github.com/Oluwatobi-Mustapha/identrail/internal/worker"
)

func main() {
	cfg := config.Load()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if err := worker.Run(context.Background(), cfg, sigCh); err != nil {
		log.Fatalf("worker failed: %v", err)
	}
}
