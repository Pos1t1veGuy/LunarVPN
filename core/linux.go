//go:build !windows

package core

import (
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"github.com/songgao/water"
)

type WaterAdapter struct {
	DefaultAdapter
	Interface *water.Interface
}

func NewWaterAdapter(name string) (*WaterAdapter, error) {
	cfg := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(cfg)
	if err != nil {
		return nil, err
	}
	// rename interface
	if name != "" {
		switch runtime.GOOS {
		case "windows":
			ExecCmd("netsh", "interface", "set", "interface",
				fmt.Sprintf(`name="%s"`, iface.Name()),
				fmt.Sprintf(`newname="%s"`, name))
		case "linux":
			ExecCmd("ip", "link", "set", "dev", iface.Name(), "down")
			ExecCmd("ip", "link", "set", "dev", iface.Name(), "name", name)
			ExecCmd("ip", "link", "set", "dev", name, "up")
		case "darwin": // macOS: utun interfaces cannot be renamed
			name = iface.Name()
		}
	}

	time.Sleep(300 * time.Millisecond)
	Interface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}

	return &WaterAdapter{
		DefaultAdapter: DefaultAdapter{
			IfaceName:  name,
			IfaceIndex: Interface.Index,
		},
		Interface: iface,
	}, nil
}
func (adapter *WaterAdapter) Read(p []byte) (int, error) {
	return adapter.Interface.Read(p)
}

func (adapter *WaterAdapter) Write(b []byte) (int, error) {
	return adapter.Interface.Write(b)
}

func (adapter *WaterAdapter) Close() {
	adapter.Interface.Close()
}

func NewLinuxServer(addr string, port int, CIDR string, LayerChains []NetLayer, authSystem Authenticator) *Server {
	serverAddrFormatted := fmt.Sprintf("%s:%d", addr, port)
	network, err := NewNetwork(CIDR)

	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "starting").
			Str("CIDR", CIDR).
			Str("serverAddr", serverAddrFormatted).
			Msg("Failed to parse CIDR")
	}
	adapter, err := NewWaterAdapter("gotun0")
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "starting").
			Str("serverAddr", serverAddrFormatted).
			Msg("Failed to create adapter")
	}

	return &Server{
		Endpoint:      *NewEndpoint(addr, port, CIDR, adapter, NewTunnel),
		Peers:         make(map[string]*Peer),
		Cache:         cache.New(30*time.Minute, 10*time.Minute),
		Network:       network,
		AnonymousPeer: NewPeer(nil, nil, nil, nil, false),
		LayerChains:   LayerChains,
		AuthSystem:    authSystem,
	}
}
