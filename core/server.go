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
	LayerChains   []NetLayer
	AuthSystem    Authenticator
	Endpoint
}

type Peer struct {
	VirtualIP  net.IP
	Addr       *net.UDPAddr
	LastSeen   time.Time
	NLChain    NetLayer
	Context    *SessionContext
	Handshaked bool
}

type SessionContext struct {
	ClientRandom [32]byte
	ServerRandom [32]byte
	MasterSecret []byte
}

func NewPeer(virtualIP net.IP, addr *net.UDPAddr, netChain NetLayer, ctx *SessionContext, handshaked bool) *Peer {
	return &Peer{
		VirtualIP:  virtualIP,
		Addr:       addr,
		LastSeen:   time.Time{},
		NLChain:    netChain,
		Context:    ctx,
		Handshaked: handshaked,
	}
}

func (server *Server) StartUnsafe(defaultLayer uint8) {
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
			Str("state", "starting").
			Str("CIDR", server.CIDR).
			Msg("Failed to parse CIDR")
	}
	server.Tunnel = server.tunFactory("", server.CIDR, "gotun0", []string{}, []string{})

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
	defer server.DisconnectAll()

	go funcSafe("UDP<=Interface", func() {
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
					peer := v.(*Peer)
					server.SendPacket(packet, peer.Addr, peer.NLChain)
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
	}, true)

	go funcSafe("UDP=>Interface", func() {
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
			v, found := server.Cache.Get(clientAddr.String())
			if !found {
				peer, err := server.Handshake(n, buf, clientAddr, defaultLayer, server.AuthSystem)
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
					peer,
					cache.DefaultExpiration,
				)

				log.Info().
					Int("len", n).
					Str("state", "U2I").
					Int("addrType", version).
					Str("peerRealIP", clientAddr.String()).
					Str("peerVirtualIP", peer.VirtualIP.String()).
					Msg("(UDP=>Interface) Handshake success")
				continue
			}

			peer := v.(*Peer)

			unwrapped, err := peer.NLChain.Wrap(buf[:n])
			if err != nil {
				log.Debug().
					Err(err).
					Int("len", n).
					Str("state", "U2I").
					Int("addrType", version).
					Msg("(UDP=>Interface) Failed to unwrap packet")
			}
			packet, err := UnmarshalPacket(unwrapped)
			if err != nil || packet.AddrType != 4 {
				log.Debug().
					Err(err).
					Int("len", n).
					Str("state", "U2I").
					Int("addrType", version).
					Msg("(UDP=>Interface) Failed to marshal packet")
				continue
			}
			if !server.PacketAPI(*server.Conn, peer, packet) {
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
			server.Cache.Set(key, peer, cache.DefaultExpiration)
		}
	}, true)

	<-sigs // waiting for Ctrl+C
	for _, peer := range server.Peers {
		if peer != nil && peer.Addr != nil {
			packet, err := MakeDisconnectPacket(server.IP, peer.VirtualIP)
			if err != nil {
				server.SendPacket(packet, peer.Addr, peer.NLChain)
			}

			log.Info().
				Str("state", "closing").
				Str("peer", peer.Addr.String()).
				Msg("disconnect packet sent")
		}
	}
	log.Info().
		Str("state", "closing").
		Msg("Server closed")
}

func (server *Server) Start(defaultLayer uint8) {
	funcSafe("mainLoop", func() { server.StartUnsafe(defaultLayer) }, false)
}

func (server *Server) DisconnectAll() {
	server.mu.RLock()
	defer server.mu.RUnlock()

	for _, peer := range server.Peers {
		if peer == nil || peer.Addr == nil {
			continue
		}

		packet, err := MakeDisconnectPacket(server.IP, peer.VirtualIP)
		if err != nil {
			log.Error().
				Err(err).
				Str("state", "closing").
				Str("peer", peer.Addr.String()).
				Msg("Failed to create disconnect packet")
			continue
		}

		server.SendPacket(packet, peer.Addr, peer.NLChain)
		log.Info().
			Str("state", "closing").
			Str("peer", peer.Addr.String()).
			Msg("Disconnect packet sent")
	}
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

// старых peer надо чистить по lastseen
// сделать базовый httpws враппер; нжинкс
// базу данных; сделать из впна микросервис докер; бота; дописать страничку
