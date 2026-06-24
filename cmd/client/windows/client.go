//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Pos1t1veGuy/LunarVPN/core"
	"github.com/Pos1t1veGuy/LunarVPN/layers"
	"github.com/rs/zerolog/log"
)

const CurrentVersion = "1.0.5"

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")

	getConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	showWindow       = user32.NewProc("ShowWindow")
)

func main() {
	validLogLevels := map[string]struct{}{
		"debug": {},
		"info":  {},
		"warn":  {},
		"error": {},
	}
	validConnTypes := map[string]func() core.Session{
		"udp":     func() core.Session { return core.NewUdpSession(5 * time.Second) },
		"udpPool": func() core.Session { return core.NewUdpSessionPool(8, 5*time.Second, 4*time.Second) },
		//"tcp":     func() core.Session { return core.NewTcpSession(5 * time.Second) },
		//"tcpPool": func() core.Session { return core.NewTcpSessionPool(8, 5*time.Second, 4*time.Second) },
	}

	appHost := flag.String("appHost", "127.0.0.1", "application host")
	appPort := flag.Int("appPort", 8080, "application port")
	serHost := flag.String("host", "", "server host")
	serPort := flag.Int("port", 0, "server port")
	login := flag.String("login", "admin", "user login")
	password := flag.String("password", "admin", "user password")
	logLevel := flag.String("logLevel", "info", "application log level (debug, info, warn, error)")
	connType := flag.String("connType", "udpPool", "type of connection to server (udp, udpPool)")
	defaultLayer := flag.Int(
		"defaultLayer",
		1,
		"layer using to handshake (use -listLayers to view, by default using Xor -defaultLayer=1)",
	)
	layersArg := flag.String(
		"layers",
		"1",
		"comma-separated layer indexes, e.g. 1,4,5 (use -listLayers to view, by default using Xor -laysers=1)",
	)
	cipherKey := flag.String(
		"cipherKey",
		"LunarVPN",
		"Key to encrypt network traffic \"[a-z][0-9]_-\"",
	)
	listLayers := flag.Bool(
		"listLayers",
		false,
		"print available layers and exit",
	)
	version := flag.Bool(
		"version",
		false,
		"print version and exit",
	)
	hideConsole := flag.Bool(
		"hideConsole",
		false,
		"hide client console log",
	)
	openTunnel := flag.Bool(
		"openTunnel",
		true,
		"opens a tunnel on a start. A tunnel is a system interface that allows traffic to be routed from the system"+
			"to the network via a VPN. It may be started/closed on a start or after some time if you want. By default 'true'",
	)
	wlPath := flag.String(
		"whitelist",
		"whitelist.txt",
		"path to whitelist file",
	)
	blPath := flag.String(
		"blacklist",
		"blacklist.txt",
		"path to blacklist file",
	)
	logFilePath := flag.String(
		"logfile",
		"",
		"path to logfile (by default logfile=\"\", so it is disabled)",
	)
	flag.Parse()
	if *version {
		fmt.Println(CurrentVersion)
		os.Exit(0)
	}
	if *hideConsole {
		hwnd, _, _ := getConsoleWindow.Call()
		if hwnd != 0 {
			showWindow.Call(hwnd, uintptr(0))
		}
	}

	lrs := []core.NetLayer{
		core.NewDebugLayer(false, false),
		layers.NewXorLayer([]byte(*cipherKey)),
	}
	if *listLayers {
		fmt.Println("Available layers:")
		for i, l := range lrs {
			fmt.Printf("  [%d] %s\n", i, l.GetDescription())
		}
		os.Exit(0)
	}

	if _, ok := validLogLevels[*logLevel]; !ok {
		_, _ = fmt.Fprintf(os.Stderr, "invalid logLevel: %q\n", *logLevel)
		flag.Usage()
		os.Exit(1)
	}
	core.InitLogger(*logLevel, *logFilePath)

	if _, ok := validConnTypes[*connType]; !ok {
		_, _ = fmt.Fprintf(os.Stderr, "invalid connType: %q\n", *connType)
		flag.Usage()
		os.Exit(1)
	}

	layersIndexes, err := parseLayers(*layersArg, lrs)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse layers")
		os.Exit(1)
	}

	whitelist, err := loadListFile(*wlPath, "# Place IPs line by line to exclude them from routing.\n"+
		"# Don't enter IP addresses if you want to route all system traffic.\n\n")
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "whiteListSetup").
			Str("path", *wlPath).
			Msg("Failed to load whitelist")
		flag.Usage()
	}
	blacklist, err := loadListFile(*blPath, "# Place IPs line by line to include them to routing.\n\n")
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "blackListSetup").
			Str("path", *blPath).
			Msg("Failed to load blacklist")
		flag.Usage()
	}

	if *serHost == "" || *serPort == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Error: both -host and -port must be specified\n\n")
		flag.Usage()
		os.Exit(1)
	}

	cl := core.NewWindowsClient(CurrentVersion, *appHost, *appPort, whitelist, blacklist, lrs, validConnTypes[*connType](), *openTunnel)
	connected := cl.Connect(*serHost, *serPort, *login, *password, layersIndexes, uint8(*defaultLayer))
	if connected == true {
		cl.Listen()
	} else {
		log.Fatal().
			Str("state", "starting").
			Str("host", *serHost).
			Int("port", *serPort).
			Msg("Can not connect to server")
	}
}

func loadListFile(path string, defaultContent string) ([]string, error) {
	if err := ensureFile(path, defaultContent); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	whitelist := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue // comment in whitelist
		}

		whitelist = append(whitelist, line)
	}

	return whitelist, nil
}

func ensureFile(path string, content string) error {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		err = os.WriteFile(path, []byte(content), 0644)
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
	}
	return err
}

func parseLayers(input string, availableLayers []core.NetLayer) ([]uint8, error) {
	if input == "" {
		return nil, fmt.Errorf("no layers specified")
	}

	parts := strings.Split(input, ",")
	result := make([]uint8, 0, len(parts))

	for _, p := range parts {
		idx, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid layer index: %q", p)
		}

		if idx < 0 || idx >= len(availableLayers) {
			return nil, fmt.Errorf("layer index out of range: %d", idx)
		}

		result = append(result, uint8(idx))
	}

	return result, nil
}
