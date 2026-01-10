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

func ConfigTunnel(destinationIP string, netCidr string, interfaceIP string, IfaceName string, whitelist []string) error {
	ip, ipNet, err := net.ParseCIDR(netCidr)
	if err != nil {
		log.Error().
			Err(err).
			Str("state", "configTunnel").
			Str("CIDR", netCidr).
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
	curIface, err := net.InterfaceByName(IfaceName)
	if err != nil {
		log.Error().
			Err(err).
			Str("state", "configTunnel").
			Str("ifaceName", IfaceName).
			Msg("Failed to get VPN interface")
		return err
	}
	log.Debug().
		Str("state", "configTunnel").
		Int("index", curIface.Index).
		Str("name", IfaceName).
		Msg("VPN adapter info")

	// destinationIP only for client to exclude server IP in routes
	switch runtime.GOOS {
	case "linux":
		if destinationIP != "" { // client
			// excluding route to remove connection loop
			ExecCmd("ip", "route", "add", destinationIP, "dev", "eth0")
		} else { // server
			// enable NAT
			ExecCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
			ExecCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", netCidr, "-o", "eth0", "-j", "MASQUERADE")
		}

		ifaceMaskOnes, _ := ipNet.Mask.Size()
		// tun interface off
		ExecCmd("ip", "link", "set", "dev", IfaceName, "down")
		// clear old IPs
		ExecCmd("ip", "addr", "flush", "dev", IfaceName)
		// make interface net
		ExecCmd("ip", "addr", "add", fmt.Sprintf("%s/%d", interfaceIP, ifaceMaskOnes), "dev", IfaceName)
		// set mtu
		ExecCmd("ip", "link", "set", "dev", IfaceName, "mtu", "1500")
		// turn interface on
		ExecCmd("ip", "link", "set", "dev", IfaceName, "up")

		//ExecCmd("ip", "route", "add", "1.1.1.1", "dev", IfaceName) // dns
	case "darwin":
		log.Error().
			Err(err).
			Str("state", "configTunnel").
			Str("CIDR", netCidr).
			Msg("Darwin not yet supported")
		return errors.New("darwin not yet supported")
	case "windows":
		ifaceMask := net.IP(ipNet.Mask).String()
		gatewayIP := ip.String()

		// set interface IP
		ExecCmd("cmd", "/C", fmt.Sprintf(`netsh interface ipv4 set address name="%s" static %s mask=%s`,
			IfaceName, interfaceIP, ifaceMask))
		// set metric to interface
		ExecCmd("netsh", "interface", "ipv4", "set", "interface", strconv.Itoa(curIface.Index), "metric=1")

		if destinationIP != "" { // client
			if len(whitelist) == 0 {
				// excluding route to remove connection loop
				ExecCmd("route", "add", destinationIP, "mask", "255.255.255.255", defIfaceIP.String(),
					"metric", "1", "if", strconv.Itoa(defIfaceIndex))
				// add absolute route to interface
				ExecCmd("route", "add", "0.0.0.0", "mask", "0.0.0.0", "0.0.0.0", "metric", "1",
					"if", strconv.Itoa(curIface.Index))
			} else {
				for _, addr := range whitelist { // TODO: make DNS resolver
					ip := net.ParseIP(addr)
					if ip != nil && ip.IsGlobalUnicast() {
						ExecCmd("route", "add", addr, "mask", "255.255.255.255", gatewayIP, "metric", "1",
							"if", strconv.Itoa(curIface.Index))
					} else {
						log.Error().
							Str("addr", addr).
							Msg("Failed to parse IP address")
					}
				}
			}
		}

		//// add dns route
		//ExecCmd("netsh", "interface", "ipv4", "set", "dns", fmt.Sprintf("name=%d", IfaceName),
		//	fmt.Sprintf("static=%d", ip.String()))

	default:
		return fmt.Errorf("not support os:%v", runtime.GOOS)
	}
	return nil
}

func ExecCmd(c string, args ...string) string {
	cmd := exec.Command(c, args...)
	var out bytes.Buffer
	err := cmd.Run()
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
		Msg("Failed to execute command")
	return result
}

func getDefaultInterface() (string, net.IP, int, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		fmt.Println("Error:", err)
		return "", nil, 0, nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error getting interfaces:", err)
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

func InitLogger(levelStr string) {
	stdlog.SetOutput(io.Discard)
	zerolog.TimeFieldFormat = time.RFC3339

	level, err := zerolog.ParseLevel(strings.ToLower(levelStr))
	if err != nil {
		level = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(level)
	cw := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "15:04:05",
	}

	log.Logger = log.Output(&SyncWriter{w: cw})
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse log level")
	}
}
