package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
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
	TcpListener   net.Listener
	AnonymousPeer *Peer
	LayerChains   []NetLayer
	AuthSystem    Authenticator

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	Endpoint
}

type Peer struct {
	VirtualIP   net.IP
	Addr        *Address
	ConnectedAt time.Time
	NLChain     NetLayer
	Context     *SessionContext
	Handshaked  bool

	TcpConn   *net.TCPConn
	tcpBuffer []byte
	tcpMu     sync.RWMutex
}

func (p *Peer) TcpWrite(data []byte) (int, error) {
	p.tcpMu.Lock()
	defer p.tcpMu.Unlock()

	if p.TcpConn == nil {
		return 0, fmt.Errorf("tcp connection is nil")
	}
	return p.TcpConn.Write(data)
}

type SessionContext struct {
	ClientRandom [32]byte
	ServerRandom [32]byte
	MasterSecret []byte
}

func NewPeer(virtualIP net.IP, addr *Address, netChain NetLayer, ctx *SessionContext, handshaked bool) *Peer {
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
	server.ctx, server.cancel = context.WithCancel(context.Background())

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
			Msg("Failed to resolve server udp address")
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", server.FullAddr)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "starting").
			Str("serverAddr", server.FullAddr).
			Msg("Failed to resolve server tcp address")
	}

	server.Conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "starting").
			Str("addr", server.FullAddr).
			Msg("Failed to start udp server")
	}
	server.TcpListener, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "starting").
			Str("addr", server.FullAddr).
			Msg("Failed to start udp server")
	}
	defer server.Stop()

	log.Info().
		Err(err).
		Str("state", "starting").
		Str("addr", server.FullAddr).
		Msg("VPN server listening")

	if err := server.Conn.SetReadBuffer(16 * 1024 * 1024); err != nil {
		log.Fatal().
			Err(err).
			Str("state", "starting").
			Str("addr", server.FullAddr).
			Msg("Failed to set write buffer")
	}
	if err := server.Conn.SetWriteBuffer(16 * 1024 * 1024); err != nil {
		log.Fatal().
			Err(err).
			Str("state", "starting").
			Str("addr", server.FullAddr).
			Msg("Failed to set read buffer")
	}

	err = server.Tunnel.Start(interfaceIP.String())
	if err != nil {
		return
	}
	defer server.Tunnel.Stop()

	log.Info().
		Str("state", "starting").
		Str("serverAddr", server.FullAddr).
		Msg("Tunnel started")

	server.MakeInterfacePipe()
	server.MakeUdpPipe(defaultLayer)
	server.ListenAndServeTCP(defaultLayer)
	<-sigs // waiting for Ctrl+C
}

func (server *Server) Start(defaultLayer uint8) {
	funcSafe("StartLoop", func() { server.StartUnsafe(defaultLayer) }, false)
}

func (server *Server) Stop() {
	server.mu.Lock()
	defer server.mu.Unlock()

	for _, peer := range server.Peers {
		if peer != nil && peer.Addr != nil {
			packet, err := MakeDisconnectPacket(server.IP, peer.VirtualIP)
			if err != nil {
				server.SendPacket(packet, peer)
			}

			log.Info().
				Str("state", "closing").
				Str("peer", peer.Addr.String()).
				Msg("disconnect packet sent")
		}
	}

	server.cancel()
	_ = server.Conn.Close()

	if server.TcpListener != nil {
		_ = server.TcpListener.Close()
	}

	log.Info().
		Str("state", "closing").
		Msg("Server closed")
}

func (server *Server) MakeInterfacePipe() {
	pipeName := "Net<=Interface"
	go funcSafe(pipeName, func() {
		server.wg.Add(1)
		defer server.wg.Done()
		buffer := make([]byte, 1500)
		pipe := fmt.Sprintf("(%s) ", pipeName)
		var key string

		for {
			select {
			case <-server.ctx.Done():
				return
			default:
			}

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
						Str("state", "I2N").
						Int("len", n).
						Str("srcIP", ip4.SrcIP.String()).
						Str("dstIP", ip4.DstIP.String()).
						Msg(pipe + "Failed to make a packet")
					continue
				}
				key = fmt.Sprintf("%v=>%v", packet.DstIP, packet.SrcIP)
				v, ok := server.Cache.Get(key)
				if ok {
					server.SendPacket(packet, v.(*Peer))
				} else {
					log.Debug().
						Str("state", "I2N").
						Int("len", n).
						Int("addrType", int(packet.AddrType)).
						Str("srcIP", ip4.SrcIP.String()).
						Str("dstIP", ip4.DstIP.String()).
						Msg(pipe + "Can not find peer receiver")
				}

			case 6:
				//gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv6, gopacket.NoCopy)
				//ip6 := gop.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				//log.Warn().
				//	Int("len", n).
				//	Str("state", "I2N").
				//	Int("addrType", int(version)).
				//	Str("key", key).
				//	Msg(pipe+"IPv6 not supported")
				continue

			default:
				continue
			}
		}
	}, true)
}

func (server *Server) MakeUdpPipe(authLayer uint8) {
	pipeType := "UDP"

	go funcSafe(pipeType+"=>Interface", func() {
		server.wg.Add(1)
		defer server.wg.Done()
		buf := make([]byte, 1500)
		pipe := fmt.Sprintf("(%s=>Interface) ", pipeType)

		for {
			select {
			case <-server.ctx.Done():
				return
			default:
			}

			n, peerAddr, err := server.Conn.ReadFromUDP(buf)
			if err != nil || n == 0 {
				continue
			}
			var version int
			if peerAddr.IP.To4() != nil {
				version = 4
			} else {
				version = 6
			}

			// auth
			peer, found := server.Peers[peerAddr.String()]
			if !found {
				writeFunc := func(payload []byte) (int, error) {
					return server.Conn.WriteToUDP(payload, peerAddr)
				}
				peer, err = server.Handshake(n, buf, NewAddressFromUDP(peerAddr), authLayer, server.AuthSystem, writeFunc)
				if err != nil || !peer.Handshaked {
					log.Error().
						Err(err).
						Int("len", n).
						Str("state", "U2I").
						Int("addrType", version).
						Str("peerAddr", peerAddr.String()).
						Msg(pipe + "Handshake failed")
					continue
				}
				server.Peers[peerAddr.String()] = peer

				log.Info().
					Int("len", n).
					Str("state", "U2I").
					Int("addrType", version).
					Str("peerRealAddr", peerAddr.String()).
					Str("peerVirtualIP", peer.VirtualIP.String()).
					Msg(pipe + "Handshake success")
				continue
			}

			unwrapped, err := peer.NLChain.Wrap(buf[:n])
			if err != nil {
				log.Debug().
					Err(err).
					Int("len", n).
					Str("state", "U2I").
					Int("addrType", version).
					Msg(pipe + "Failed to unwrap packet")
			}
			packet, err := UnmarshalPacket(unwrapped)
			if err != nil || packet.AddrType != 4 {
				log.Debug().
					Err(err).
					Int("len", n).
					Str("state", "U2I").
					Int("addrType", version).
					Msg(pipe + "Failed to marshal packet")
				continue
			}
			if !server.PacketAPI(server.Conn, peer, packet) {
				if _, err := server.Interface.Write(packet.Data); err != nil {
					log.Debug().
						Err(err).
						Int("len", n).
						Str("state", "U2I").
						Int("addrType", version).
						Str("srcIP", packet.SrcIP.String()).
						Str("dstIP", packet.DstIP.String()).
						Msg(pipe + "Failed to send packet")
				} else {
					log.Debug().
						Int("len", n).
						Str("state", "U2I").
						Int("addrType", version).
						Str("srcIP", packet.SrcIP.String()).
						Str("dstIP", packet.DstIP.String()).
						Msg(pipe + "Sent a packet")
				}
				key := fmt.Sprintf("%v=>%v", packet.SrcIP, packet.DstIP)
				server.Cache.Set(key, peer, cache.DefaultExpiration)
			} else {
				log.Debug().
					Int("len", n).
					Str("state", "U2I").
					Int("addrType", version).
					Str("srcIP", packet.SrcIP.String()).
					Str("dstIP", packet.DstIP.String()).
					Msg(pipe + "Got API packet")
			}
		}
	}, true)
}

func (server *Server) MakeTcpPipe(authLayer uint8, peer *Peer) {
	pipeType := "TCP"
	pipe := fmt.Sprintf("(%s=>Interface) ", pipeType)
	peer.tcpBuffer = make([]byte, 0)

	readBuf := make([]byte, 4096)
	writeFunc := func(payload []byte) (int, error) { return peer.TcpWrite(payload) }

	go funcSafe(pipeType+"=>Interface", func() {
		defer server.DisconnectPeer(peer)
		for {
			select {
			case <-server.ctx.Done():
				return
			default:
			}

			n, err := peer.TcpConn.Read(readBuf)
			if err != nil {
				log.Debug().
					Err(err).
					Str("state", "T2I").
					Str("peer", peer.Addr.String()).
					Msg(pipe + "Сonnection closed")
				return
			}

			peer.tcpBuffer = append(peer.tcpBuffer, readBuf[:n]...)

			for {
				completed, bytes := ExtractPacket(peer.tcpBuffer)
				if !completed {
					break
				}
				if bytes.Err != nil {
					log.Warn().
						Err(bytes.Err).
						Str("state", "T2I").
						Str("peer", peer.Addr.String()).
						Msg("Protocol error")
					return
				}
				peer.tcpBuffer = bytes.RemainingBuf

				if !peer.Handshaked {
					newPeer, err := server.Handshake(len(bytes.CompletePacket), bytes.CompletePacket, peer.Addr,
						authLayer, server.AuthSystem, writeFunc)
					if err != nil || !newPeer.Handshaked {
						log.Error().Err(err).Str("peer", peer.Addr.String()).Msg("Handshake failed")
						return
					}

					peer.VirtualIP = newPeer.VirtualIP
					peer.Context = newPeer.Context
					peer.NLChain = newPeer.NLChain
					peer.Handshaked = true

					server.mu.Lock()
					server.Peers[peer.Addr.String()] = peer
					server.mu.Unlock()

					log.Info().
						Str("state", "T2I").
						Str("peerRealAddr", peer.Addr.String()).
						Str("peerVirtualIP", peer.VirtualIP.String()).
						Msg(pipe + "Handshake success")
				}

				unwrapped, err := peer.NLChain.Wrap(bytes.CompletePacket)
				if err != nil {
					log.Debug().
						Err(err).
						Str("state", "T2I").
						Str("peer", peer.Addr.String()).
						Msg(pipe + "Failed to unwrap packet")
					continue
				}
				packet, err := UnmarshalPacket(unwrapped)
				if err != nil {
					log.Debug().
						Err(err).
						Str("state", "T2I").
						Str("peer", peer.Addr.String()).
						Str("srcIP", packet.SrcIP.String()).
						Str("dstIP", packet.DstIP.String()).
						Msg(pipe + "Failed to unmarshal packet")
					continue
				}

				if !server.PacketAPI(peer.TcpConn, peer, packet) {
					if _, err := server.Interface.Write(packet.Data); err != nil {
						log.Debug().
							Err(err).
							Str("state", "T2I").
							Str("peer", peer.Addr.String()).
							Str("srcIP", packet.SrcIP.String()).
							Str("dstIP", packet.DstIP.String()).
							Msg(pipe + "Failed to write to Interface")
					} else {
						key := fmt.Sprintf("%v=>%v", packet.SrcIP, packet.DstIP)
						server.Cache.Set(key, peer, cache.DefaultExpiration)
					}
				} else {
					log.Debug().
						Str("state", "T2I").
						Str("peer", peer.Addr.String()).
						Str("srcIP", packet.SrcIP.String()).
						Str("dstIP", packet.DstIP.String()).
						Msg(pipe + "Got API packet")
				}
			}
		}
	}, true)
}

func (server *Server) ListenAndServeTCP(authLayer uint8) {
	go funcSafe("TcpListener", func() {
		for {
			select {
			case <-server.ctx.Done():
				return
			default:
			}

			conn, err := server.TcpListener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "closed") {
					log.Error().Err(err).Msg("TCP accept error")
				}
				continue
			}

			tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
			if !ok {
				_ = conn.Close()
				continue
			}
			clientAddr := NewAddressFromTCP(tcpAddr)

			peer := NewPeer(nil, clientAddr, server.LayerChains[authLayer], nil, false)
			tcpConn, ok := conn.(*net.TCPConn)
			if ok {
				err = tcpConn.SetNoDelay(true)
				if err != nil {
					log.Warn().Err(err).Msg("Failed to SetNoDelay")
				}

				err = tcpConn.SetKeepAlive(true)
				if err != nil {
					log.Warn().Err(err).Msg("Failed to SetKeepAlive")
				}
			}
			peer.TcpConn = tcpConn

			go server.MakeTcpPipe(authLayer, peer)
		}
	}, true)
}

func (server *Server) DisconnectPeer(peer *Peer) (err error) {
	packet, err := MakeDisconnectPacket(server.IP, peer.VirtualIP)
	if err != nil {
		log.Error().
			Err(err).
			Str("state", "closing").
			Str("peer", peer.Addr.String()).
			Msg("Failed to create disconnect packet")
	} else {
		server.SendPacket(packet, peer)
	}

	server.mu.Lock()
	defer server.mu.Unlock()

	log.Info().
		Str("state", "closing").
		Str("peer", peer.Addr.String()).
		Msg("Disconnect packet sent")

	delete(server.Peers, peer.Addr.String())
	delete(server.Network.Used, peer.VirtualIP.String())

	if peer.TcpConn != nil {
		_ = peer.TcpConn.Close()
	}
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
			return nil, fmt.Errorf("no free IPs left")
		}

		currentIP := intToIP(network.Current)
		ipStr := currentIP.String()
		if _, exists := network.Used[ipStr]; !exists {
			network.Used[ipStr] = struct{}{}
			network.increment()
			return currentIP, nil
		}

		network.increment()
		time.Sleep(1 * time.Millisecond)
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
