package core

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Endpoint struct {
	Addr     string
	IP       net.IP
	Port     int
	FullAddr string
	CIDR     string

	Net  *net.IPNet
	Conn *net.UDPConn
}

func NewEndpoint(addr string, port int, CIDR string) *Endpoint {
	_, ipNet, err := net.ParseCIDR(CIDR)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "factory").
			Str("CIDR", CIDR).
			Msg("Failed to parse CIDR")
	}

	return &Endpoint{
		Addr:     addr,
		IP:       net.ParseIP(addr),
		Port:     port,
		FullAddr: fmt.Sprintf("%s:%d", addr, port),
		CIDR:     CIDR,
		Net:      ipNet,
	}
}

type Tunnel struct {
	DestinationIP string
	Whitelist     []string
	Blacklist     []string
	IfaceName     string
	InterfaceIP   string
	NetCIDR       string

	bypassingIPs []string
}

func NewTunnel(destinationIP string, netCidr string, IfaceName string, whitelist []string, blacklist []string) *Tunnel {
	return &Tunnel{
		DestinationIP: destinationIP,
		Whitelist:     whitelist,
		Blacklist:     blacklist,
		IfaceName:     IfaceName,
		NetCIDR:       netCidr,
	}
}

func (tunnel *Tunnel) Start(interfaceIP string) error {
	tunnel.InterfaceIP = interfaceIP

	ip, ipNet, err := net.ParseCIDR(tunnel.NetCIDR)
	if err != nil {
		log.Error().
			Err(err).
			Str("state", "configTunnel").
			Str("CIDR", tunnel.NetCIDR).
			Msg("Failed to parse CIDR")
		return err
	}

	// getting interfaces info
	defIfaceName, defIfaceIP, defIfaceIndex, err := getDefaultInterface()
	if err != nil {
		log.Error().
			Err(err).
			Str("state", "configTunnel").
			Msg("Failed to get default interface")
		return err
	}
	log.Debug().
		Str("state", "configTunnel").
		Int("index", defIfaceIndex).
		Str("name", defIfaceName).
		Str("ip", defIfaceIP.String()).
		Msg("Default adapter info")
	curIface, err := net.InterfaceByName(tunnel.IfaceName)
	if err != nil {
		log.Error().
			Err(err).
			Str("state", "configTunnel").
			Str("ifaceName", tunnel.IfaceName).
			Msg("Failed to get VPN interface")
		return err
	}
	log.Debug().
		Str("state", "configTunnel").
		Int("index", curIface.Index).
		Str("name", tunnel.IfaceName).
		Msg("VPN adapter info")

	// destinationIP only for client to exclude server IP in routes
	switch runtime.GOOS {
	case "linux":
		if tunnel.DestinationIP != "" { // client
			if len(tunnel.Whitelist) == 0 {
				defGatewayIP, err := getDefaultGatewayLinux()
				if err != nil {
					log.Error().
						Err(err).
						Str("state", "configTunnel").
						Msg("Cannot get default gateway")
				}

				// excluding route to remove connection loop
				ExecCmd("ip", "route", "add", tunnel.DestinationIP, "dev", tunnel.IfaceName)
				// Route all
				ExecCmd("ip", "route", "add", "default", "dev", tunnel.IfaceName)

				log.Info().
					Str("state", "configTunnel").
					Msg("Routed all IPs into tunnel")

				for _, addr := range tunnel.Blacklist {
					ip := net.ParseIP(addr)
					if ip != nil && ip.IsGlobalUnicast() && addr != tunnel.DestinationIP {
						ExecCmd("ip", "route", "add", addr, "via", defGatewayIP.String(), "dev", "eth0")
						log.Info().
							Str("state", "configTunnel").
							Str("addr", addr).
							Msg("Routed bypassing the tunnel")
						tunnel.bypassingIPs = append(tunnel.bypassingIPs, addr)
					} else {
						log.Error().
							Str("state", "configTunnel").
							Str("addr", addr).
							Msg("Failed to parse IP address")
					}
				}
			}
			for _, addr := range tunnel.Whitelist {
				ip := net.ParseIP(addr)
				if ip != nil && ip.IsGlobalUnicast() && !contains(tunnel.Blacklist, addr) {
					ExecCmd("ip", "route", "add", addr, "dev", tunnel.IfaceName)
					log.Info().
						Str("state", "configTunnel").
						Str("addr", addr).
						Msg("Routed IP into tunnel")
				} else {
					log.Error().
						Str("state", "configTunnel").
						Str("addr", addr).
						Msg("Failed to parse IP address")
				}
			}
		} else { // server
			// enable NAT
			ExecCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
			ExecCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", tunnel.NetCIDR, "-o", "eth0", "-j", "MASQUERADE")
			// set mss
			ExecCmd(
				"iptables", "-t", "mangle", "-A", "FORWARD",
				"-i", tunnel.IfaceName,
				"-p", "tcp",
				"--tcp-flags", "SYN,RST", "SYN",
				"-j", "TCPMSS",
				"--clamp-mss-to-pmtu",
			)
			ExecCmd(
				"iptables", "-t", "mangle", "-A", "FORWARD",
				"-o", tunnel.IfaceName,
				"-p", "tcp",
				"--tcp-flags", "SYN,RST", "SYN",
				"-j", "TCPMSS",
				"--clamp-mss-to-pmtu",
			)
		}

		ifaceMaskOnes, _ := ipNet.Mask.Size()
		// tun interface off
		ExecCmd("ip", "link", "set", "dev", tunnel.IfaceName, "down")
		// clear old IPs
		ExecCmd("ip", "addr", "flush", "dev", tunnel.IfaceName)
		// make interface net
		ExecCmd("ip", "addr", "add",
			fmt.Sprintf("%s/%d", tunnel.InterfaceIP, ifaceMaskOnes), "dev", tunnel.IfaceName)
		// set mtu
		ExecCmd("ip", "link", "set", "dev", tunnel.IfaceName, "mtu", strconv.Itoa(MaxPayload))
		// turn interface on
		ExecCmd("ip", "link", "set", "dev", tunnel.IfaceName, "up")

	case "darwin":
		log.Error().
			Err(err).
			Str("state", "configTunnel").
			Str("CIDR", tunnel.NetCIDR).
			Msg("Darwin not yet supported")
		return errors.New("darwin not yet supported")

	case "windows":
		ifaceMask := net.IP(ipNet.Mask).String()
		gatewayIP := ip.String()

		// set interface IP
		ExecCmd("cmd", "/C", fmt.Sprintf(`netsh interface ipv4 set address name="%s" static %s mask=%s`,
			tunnel.IfaceName, tunnel.InterfaceIP, ifaceMask))
		// set metric to interface
		ExecCmd("netsh", "interface", "ipv4", "set", "interface", strconv.Itoa(curIface.Index), "metric=1")
		// set mtu to interface
		ExecCmd(
			"netsh",
			"interface",
			"ipv4",
			"set",
			"subinterface",
			fmt.Sprintf(`"%s"`, tunnel.IfaceName),
			fmt.Sprintf("mtu=%d", MaxPayload),
			"store=persistent",
		)

		if tunnel.DestinationIP != "" { // client
			// add dns route
			ExecCmd("netsh", "interface", "ipv4", "set", "dns", fmt.Sprintf(`name="%s"`, tunnel.IfaceName),
				"static", "8.8.8.8")
			ExecCmd("netsh", "interface", "ipv4", "add", "dns", fmt.Sprintf(`name="%s"`, tunnel.IfaceName),
				"addr=1.1.1.1", "index=2")

			if len(tunnel.Whitelist) == 0 {
				// excluding route to remove connection loop
				defGatewayIP, err := getDefaultGatewayWindows()
				if err != nil {
					log.Error().
						Err(err).
						Str("state", "configTunnel").
						Msg("Can not get default gateway")
				}

				ExecCmd("route", "add", tunnel.DestinationIP, "mask", "255.255.255.255", defGatewayIP.String(),
					"metric", "1", "if", strconv.Itoa(defIfaceIndex))
				// add absolute route to interface
				ExecCmd("route", "add", "0.0.0.0", "mask", "0.0.0.0", "0.0.0.0", "metric", "1",
					"if", strconv.Itoa(curIface.Index))
				log.Info().
					Str("state", "configTunnel").
					Msg("Routed all IPs into tunnel")

				for _, addr := range tunnel.Blacklist {
					ip := net.ParseIP(addr)
					if ip != nil && ip.IsGlobalUnicast() && addr != tunnel.DestinationIP {
						ExecCmd("route", "add", addr, "mask", "255.255.255.255", defGatewayIP.String(), "metric", "1",
							"if", strconv.Itoa(defIfaceIndex))
						log.Info().
							Str("state", "configTunnel").
							Str("addr", addr).
							Msg("Routed bypassing the tunnel")
						tunnel.bypassingIPs = append(tunnel.bypassingIPs, addr)
					} else {
						log.Error().
							Str("state", "configTunnel").
							Str("addr", addr).
							Msg("Failed to parse IP address")
					}
				}
			}
			for _, addr := range tunnel.Whitelist {
				ip := net.ParseIP(addr)
				if ip != nil && ip.IsGlobalUnicast() && !contains(tunnel.Blacklist, addr) {
					ExecCmd("route", "add", addr, "mask", "255.255.255.255", gatewayIP, "metric", "1",
						"if", strconv.Itoa(curIface.Index))
					log.Info().
						Str("state", "configTunnel").
						Str("addr", addr).
						Msg("Routed IP into tunnel")
				} else {
					log.Error().
						Str("state", "configTunnel").
						Str("addr", addr).
						Msg("Failed to parse IP address")
				}
			}
		}

	default:
		return fmt.Errorf("not support os:%v", runtime.GOOS)
	}
	return nil
}

func (tunnel *Tunnel) Stop() {
	if tunnel.DestinationIP != "" && len(tunnel.Whitelist) != 0 {
		switch runtime.GOOS {
		case "windows":
			ExecCmd("route", "delete", tunnel.DestinationIP)
			for _, addr := range tunnel.Blacklist {
				ExecCmd("route", "delete", addr)
			}
		case "linux":
			ExecCmd("ip", "route", "del", tunnel.DestinationIP)
			for _, addr := range tunnel.Blacklist {
				ExecCmd("ip", "route", "del", addr)
			}
		}
	}
}

func ExecCmd(c string, args ...string) string {
	cmd := exec.Command(c, args...)
	var out bytes.Buffer
	err := cmd.Run()
	cmd.Stdout = &out
	if err != nil {
		log.Error().
			Err(err).
			Str("state", "exec").
			Str("bin", cmd.Path).
			Strs("cmd", cmd.Args).
			Msg("Failed to execute command")
	}
	result := strings.TrimSpace(out.String())
	log.Debug().
		Str("state", "exec").
		Str("bin", cmd.Path).
		Strs("cmd", cmd.Args).
		Str("result", result).
		Msg("command executed")
	return result
}

func getDefaultInterface() (string, net.IP, int, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", nil, 0, nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", localAddr.IP, 0, nil
	}

	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			if ipnet.IP.Equal(localAddr.IP) {
				return iface.Name, localAddr.IP, iface.Index, nil
			}
		}
	}
	return "", localAddr.IP, 0, nil
}

func getDefaultGatewayWindows() (net.IP, error) {
	out, err := exec.Command("cmd", "/C", "route print 0.0.0.0").Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 &&
			fields[0] == "0.0.0.0" &&
			fields[1] == "0.0.0.0" {

			gw := net.ParseIP(fields[2]).To4()
			if gw != nil && gw[0] == 192 && gw[1] == 168 {
				return gw, nil
			}
		}
	}
	return nil, errors.New("default gateway not found")
}

func getDefaultGatewayLinux() (net.IP, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run 'ip route': %w", err)
	}

	lines := bytes.Split(out, []byte("\n"))
	for _, line := range lines {
		fields := strings.Fields(string(line))
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				gw := net.ParseIP(fields[i+1])
				if gw != nil {
					return gw, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("default gateway not found")
}

type InterfaceAdapter interface {
	Name() string
	Index() int
	Read(p []byte) (int, error)
	Write(b []byte) (int, error)
	Close()
}

type DefaultAdapter struct {
	IfaceName  string
	IfaceIndex int
}

func (adapter *DefaultAdapter) Name() string {
	return adapter.IfaceName
}
func (adapter *DefaultAdapter) Index() int {
	return adapter.IfaceIndex
}

type SyncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *SyncWriter) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func InitLogger(levelStr string, filename string) {
	stdlog.SetOutput(io.Discard)
	zerolog.TimeFieldFormat = time.RFC3339

	level, err := zerolog.ParseLevel(strings.ToLower(levelStr))
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	var out io.Writer
	if filename != "" {
		file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal().
				Err(err).
				Str("state", "logSetup").
				Msg("Cannot open log file")
		}

		out = io.MultiWriter(os.Stdout, file)
	} else {
		out = os.Stdout
	}
	cw := zerolog.ConsoleWriter{
		Out:        out,
		TimeFormat: "15:04:05",
	}

	log.Logger = log.Output(&SyncWriter{w: cw})
	if err != nil {
		log.Error().
			Err(err).
			Str("state", "logSetup").
			Msg("Failed to parse log level")
	}
}

func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func funcSafe(name string, fn func(), autoRestart bool) {
	func() {
		defer func() {
			if r := recover(); r != nil {
				if autoRestart {
					funcSafe(name, fn, autoRestart)
					log.Error().
						Str("goroutine", name).
						Interface("panic", r).
						Bytes("stack", debug.Stack()).
						Msg("goroutine panicked, restarting")
				} else {
					log.Error().
						Str("goroutine", name).
						Interface("panic", r).
						Bytes("stack", debug.Stack()).
						Msg("goroutine panicked and disabled")
				}
			}
		}()
		fn()
	}()
}
