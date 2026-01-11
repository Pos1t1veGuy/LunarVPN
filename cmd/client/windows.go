//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Pos1t1veGuy/MoonVPN/core"
	"github.com/rs/zerolog/log"
)

func main() {
	validLogLevels := map[string]struct{}{
		"debug": {},
		"info":  {},
		"warn":  {},
		"error": {},
	}

	appHost := flag.String("appHost", "127.0.0.1", "application host")
	appPort := flag.Int("appPort", 8080, "application port")
	serHost := flag.String("host", "194.41.113.111", "server host")
	serPort := flag.Int("port", 5555, "server port")
	logLevel := flag.String("logLevel", "info", "application log level (debug, info, warn, error)")
	flag.Parse()

	if _, ok := validLogLevels[*logLevel]; !ok {
		fmt.Fprintf(os.Stderr, "invalid logLevel: %q\n", *logLevel)
		os.Exit(1)
	}

	core.InitLogger(*logLevel)
	cl := core.NewWindowsClient(*appHost, *appPort, []string{})
	connected := cl.Connect(*serHost, *serPort)
	if connected == true {
		cl.Listen()
	} else {
		log.Fatal().
			Str("host", *serHost).
			Int("port", *serPort).
			Msg("Can not connect to server")
	}
}
