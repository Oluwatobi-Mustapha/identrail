package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Oluwatobi-Mustapha/accessloom/internal/config"
	"github.com/Oluwatobi-Mustapha/accessloom/internal/server"
)

func main() {
	cfg := config.Load()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if err := server.Run(context.Background(), cfg, sigCh); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
