package main

import (
	"os"

	"proxygo/internal/app"
	"proxygo/internal/cli"
	"proxygo/internal/privileged"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == privileged.Arg {
		os.Exit(privileged.Serve(os.Args[2:]))
	}
	if args, ok := cli.Invoked(os.Args); ok {
		os.Exit(cli.Main(args))
	}
	app.Main()
}
