package main

import (
	"os"

	"github.com/1337lean/certpulse/internal/app"
)

var version = "dev"

func main() { os.Exit(app.Run(os.Args[1:], os.Stdout, os.Stderr, version)) }
