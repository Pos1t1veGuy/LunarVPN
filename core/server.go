package core

import (
	"encoding/binary"
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
	VirtualIP   net.IP
	Addr        *net.UDPAddr
	ConnectedAt time.Time
	NLChain     NetLayer
	Context     *SessionContext
	Handshaked  bool
}

type SessionContext struct {
	ClientRandom [32]byte
	ServerRandom [32]byte
	MasterSecret []byte
}

func NewPeer(virtualIP net.IP, addr *net.UDPAddr, netChain NetLayer, ctx *SessionContext, handshaked bool) *Peer {
	return &Peer{
		VirtualIP:   virtualIP,
		Addr:        addr,
		ConnectedAt: time.Time{},
		NLChain:     netChain,
		Context:     ctx,
		Handshaked:  handshaked,
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
	server.Tunnel = server.tunFactory("", server.CIDR, server.Gateway, "gotun0", []string{}, []string{})

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
					log.Error().
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
			server.Cache.Set(
				clientAddr.String(),
				peer,
				cache.DefaultExpiration,
			)

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
			if !server.PacketAPI(*server.Conn, peer, packet, clientAddr) {
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
	funcSafe("StartLoop", func() { server.StartUnsafe(defaultLayer) }, false)
}

func (server *Server) DisconnectPeer(peer *Peer) (err error) {
	server.mu.Lock()
	defer server.mu.Unlock()

	packet, err := MakeDisconnectPacket(server.IP, peer.VirtualIP)
	if err != nil {
		log.Error().
			Err(err).
			Str("state", "closing").
			Str("peer", peer.Addr.String()).
			Msg("Failed to create disconnect packet")
		return err
	}

	server.SendPacket(packet, peer.Addr, peer.NLChain)
	log.Info().
		Str("state", "closing").
		Str("peer", peer.Addr.String()).
		Msg("Disconnect packet sent")

	delete(server.Peers, peer.Addr.String())
	delete(server.Network.Used, peer.VirtualIP.String())
	return nil
}

func (server *Server) DisconnectAll() {
	server.mu.RLock()
	defer server.mu.RUnlock()

	for _, peer := range server.Peers {
		if peer == nil || peer.Addr == nil {
			continue
		}
		_ = server.DisconnectPeer(peer)
	}
}

type Network struct {
	Used      map[string]struct{}
	Current   uint32
	MaxLength uint

	NetworkBits   uint32
	MaskBits      uint32
	BroadcastBits uint32
	net.IPNet
}

func NewNetwork(cidr string) (*Network, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	networkBits := binary.BigEndian.Uint32(network.IP.To4())
	ipBits := binary.BigEndian.Uint32(ip.To4())
	maskBits := binary.BigEndian.Uint32(network.Mask)
	broadcast := networkBits | (^maskBits)

	ones, _ := network.Mask.Size()
	maxLen := 1<<(32-ones) - 2

	if ip[3] == 0 {
		ip[3] = 2
	}

	return &Network{
		Used:          map[string]struct{}{ip.String(): {}, network.IP.String(): {}},
		Current:       ipBits,
		MaxLength:     uint(maxLen),
		NetworkBits:   networkBits,
		MaskBits:      maskBits,
		BroadcastBits: broadcast,
		IPNet:         *network,
	}, nil
}

func (network *Network) Next() (net.IP, error) {
	for {
		if len(network.Used) >= int(network.MaxLength) {
			fmt.Println(len(network.Used), int(network.MaxLength))
			return nil, fmt.Errorf("no free IPs left")
		}

		currentIP := intToIP(network.Current)
		fmt.Println(1, currentIP)
		ipStr := currentIP.String()
		if _, exists := network.Used[ipStr]; !exists {
			network.Used[ipStr] = struct{}{}
			network.increment()
			return currentIP, nil
		}
		fmt.Println(2, currentIP)

		network.increment()
		time.Sleep(5 * time.Millisecond)
		fmt.Println(3, currentIP)
	}
}

func (network *Network) increment() {
	hostPart := (network.Current + 1) & (^network.MaskBits)
	network.Current = network.NetworkBits | hostPart

	if network.Current > network.BroadcastBits {
		network.Current = network.NetworkBits + 1
	}
}

func intToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
