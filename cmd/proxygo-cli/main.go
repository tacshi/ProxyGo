package main

import (
	"os"

	"proxygo/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
