package core

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
)

type Server struct {
	Peers         map[string]*Peer
	mu            sync.RWMutex
	Cache         *cache.Cache
	Network       *Network
	AnonymousPeer *Peer
	Interface     InterfaceAdapter
	Tunnel        *Tunnel
	Endpoint
}

type Peer struct {
	VirtualIP  net.IP
	Addr       *net.UDPAddr
	LastSeen   time.Time
	Handshaked bool
}

func NewPeer(virtualIP net.IP, addr *net.UDPAddr, handshaked bool) *Peer {
	return &Peer{
		VirtualIP:  virtualIP,
		Addr:       addr,
		LastSeen:   time.Time{},
		Handshaked: handshaked,
	}
}

func (server *Server) Start() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	log.Info().
		Str("state", "starting").
		Str("serverAddr", server.FullAddr).
		Msg("Starting server")

	interfaceIP, _, err := net.ParseCIDR(server.CIDR)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "configTunnel").
			Str("CIDR", server.CIDR).
			Msg("Failed to parse CIDR")
	}
	server.Tunnel = NewTunnel("", server.CIDR, "gotun0", []string{})

	udpAddr, err := net.ResolveUDPAddr("udp", server.FullAddr)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "starting").
			Str("serverAddr", server.FullAddr).
			Msg("Failed to resolve server address")
	}

	server.Conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "starting").
			Str("addr", server.FullAddr).
			Msg("Failed to start server")
	}

	log.Info().
		Err(err).
		Str("state", "starting").
		Str("addr", server.FullAddr).
		Msg("VPN server listening")

	err = server.Tunnel.Start(interfaceIP.String())
	if err != nil {
		return
	}
	defer server.Tunnel.Stop()

	log.Info().
		Str("state", "starting").
		Str("serverAddr", server.FullAddr).
		Msg("Tunnel started")

	// udp <= interface
	go func() {
		buffer := make([]byte, 1500)
		var key string
		for {
			n, err := server.Interface.Read(buffer)
			if err != nil || n == 0 {
				continue
			}

			version := buffer[0] >> 4
			switch version {
			case 4:
				gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv4, gopacket.NoCopy)
				ip4 := gop.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

				packet, err := MakeDefaultPacket(ip4.SrcIP, ip4.DstIP, buffer[:n])
				if err != nil {
					log.Error().
						Err(err).
						Str("state", "I2U").
						Int("len", n).
						Str("srcIP", ip4.SrcIP.String()).
						Str("dstIP", ip4.DstIP.String()).
						Msg("(UDP<=Interface) Failed to make a packet")
					continue
				}
				key = fmt.Sprintf("%v=>%v", packet.DstIP, packet.SrcIP)
				v, ok := server.Cache.Get(key)
				if ok {
					server.SendPacket(packet, v.(*net.UDPAddr))
				} else {
					log.Debug().
						Str("state", "I2U").
						Int("len", n).
						Int("addrType", int(packet.AddrType)).
						Str("srcIP", ip4.SrcIP.String()).
						Str("dstIP", ip4.DstIP.String()).
						Msg("(UDP<=Interface) Can not find peer receiver")
				}

			case 6:
				//gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv6, gopacket.NoCopy)
				//ip6 := gop.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				//log.Warn().
				//	Int("len", n).
				//	Str("state", "I2U").
				//	Int("addrType", int(version)).
				//	Str("key", key).
				//	Msg("(UDP<=Interface) IPv6 not supported")
				continue

			default:
				continue
			}
		}
	}()

	// udp => interface
	go func() {
		buf := make([]byte, 1500)
		for {
			n, clientAddr, err := server.Conn.ReadFromUDP(buf)
			if err != nil || n == 0 {
				continue
			}
			var version int
			if clientAddr.IP.To4() != nil {
				version = 4
			} else {
				version = 6
			}

			// auth
			if _, found := server.Cache.Get(clientAddr.String()); !found {

				peer, err := server.Handshake(n, buf, clientAddr)
				if err != nil || !peer.Handshaked {
					log.Debug().
						Err(err).
						Int("len", n).
						Str("state", "U2I").
						Int("addrType", version).
						Str("peerIP", clientAddr.String()).
						Msg("(UDP=>Interface) Handshake failed")
					continue
				}

				server.Cache.Set(
					clientAddr.String(),
					clientAddr,
					cache.DefaultExpiration,
				)

				log.Info().
					Int("len", n).
					Str("state", "U2I").
					Int("addrType", version).
					Str("peerIP", clientAddr.String()).
					Msg("(UDP=>Interface) Handshake success")
				continue
			}

			packet, err := UnmarshalPacket(buf[:n])
			if !server.PacketAPI(*server.Conn, *clientAddr, packet) {
				if err != nil || packet.AddrType != 4 {
					log.Debug().
						Err(err).
						Int("len", n).
						Str("state", "U2I").
						Int("addrType", version).
						Msg("(UDP=>Interface) Failed to marshal packet")
					continue
				}

				if _, err := server.Interface.Write(packet.Data); err != nil {
					log.Debug().
						Err(err).
						Int("len", n).
						Str("state", "U2I").
						Int("addrType", version).
						Str("srcIP", packet.SrcIP.String()).
						Str("dstIP", packet.DstIP.String()).
						Msg("(UDP=>Interface) Failed to send packet")
				} else {
					log.Debug().
						Int("len", n).
						Str("state", "U2I").
						Int("addrType", version).
						Str("srcIP", packet.SrcIP.String()).
						Str("dstIP", packet.DstIP.String()).
						Msg("(UDP=>Interface) Sent a packet")
				}
			} else {
				log.Debug().
					Int("len", n).
					Str("state", "U2I").
					Int("addrType", version).
					Str("srcIP", packet.SrcIP.String()).
					Str("dstIP", packet.DstIP.String()).
					Msg("(UDP=>Interface) Got API packet")
			}

			key := fmt.Sprintf("%v=>%v", packet.SrcIP, packet.DstIP)
			server.Cache.Set(key, clientAddr, cache.DefaultExpiration)
		}
	}()

	<-sigs // waiting for Ctrl+C
	for _, peer := range server.Peers {
		if peer != nil && peer.Addr != nil {
			packet, err := MakeDisconnectPacket(server.IP, peer.VirtualIP)
			if err != nil {
				server.SendPacket(packet, peer.Addr)
			}

			log.Info().
				Str("peer", peer.Addr.String()).
				Msg("disconnect packet sent")
		}
	}
	log.Info().Msg("Server closed")
}

type Network struct {
	Used    map[string]struct{}
	Current net.IP
	net.IPNet
}

func NewNetwork(cidr string) (*Network, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	return &Network{
		Used:    map[string]struct{}{ip.String(): {}},
		Current: ip,
		IPNet:   *network,
	}, nil
}

func (network *Network) Next() (net.IP, error) {
	for {
		if !network.Contains(network.Current) {
			return nil, fmt.Errorf("no free IPs left")
		}

		ipStr := network.Current.String()
		if _, exists := network.Used[ipStr]; !exists {
			result := make(net.IP, len(network.Current))
			copy(result, network.Current)

			network.Used[ipStr] = struct{}{}
			network.increment()

			return result, nil
		}

		network.increment()
	}
}

func (network *Network) increment() {
	for i := len(network.Current) - 1; i >= 0; i-- {
		network.Current[i]++
		if network.Current[i] != 0 {
			break
		}
	}
}

// фрагментация UDP; шифрование; таймауты; старых peer надо чистить по lastseen; черные списки;
// аргументация в клиенте; сделать интерфейс врапперов; сделать базовый httpws враппер; присобачить нжинкс
// приделать базу данных; сделать из впна микросервис докер; присобачить бота; дописать страничку;
