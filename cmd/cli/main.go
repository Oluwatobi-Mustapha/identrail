package main

import (
	"fmt"
	"os"

	"github.com/Oluwatobi-Mustapha/identrail/internal/cli"
	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
)

func main() {
	cfg := config.Load()
	if err := cli.Execute(cfg, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
