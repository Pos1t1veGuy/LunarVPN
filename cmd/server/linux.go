//go:build !windows

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Pos1t1veGuy/LunarVPN/core"
	"github.com/Pos1t1veGuy/LunarVPN/layers"
)

func main() {
	validLogLevels := map[string]struct{}{
		"debug": {},
		"info":  {},
		"warn":  {},
		"error": {},
	}

	cidr := flag.String("cidr", "10.0.0.1/24", "application net interface CIDR")
	host := flag.String("host", "0.0.0.0", "application host")
	logLevel := flag.String("logLevel", "info", "application log level (debug, info, warn, error)")
	port := flag.Int("port", 5555, "application port")
	defaultLayer := flag.Int(
		"defaultLayer",
		1,
		"layer using to handshake (use -listLayers to view, by default -defaultLayer=1)",
	)
	logFilePath := flag.String(
		"logfile",
		"",
		"path to logfile file (by default logfile=\"\", so it is disabled)",
	)
	flag.Parse()

	if _, ok := validLogLevels[*logLevel]; !ok {
		fmt.Fprintf(os.Stderr, "invalid logLevel: %q\n", *logLevel)
		os.Exit(1)
	}

	lrs := []core.NetLayer{
		core.NewDebugLayer(false, false),
		layers.NewXorLayer([]byte("LunarVPN")),
	}

	core.InitLogger(*logLevel, *logFilePath)
	srv := core.NewLinuxServer(*host, *port, *cidr, lrs, &core.StaticAuth{
		Allowed: map[string]string{
			"admin": "admin",
		},
	})
	srv.Start(uint8(*defaultLayer))
}
