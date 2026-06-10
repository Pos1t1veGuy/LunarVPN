package core

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

type Client struct {
	VirtualIP   *net.IP
	ServerAddr  *Address
	WhiteList   []string
	BlackList   []string
	LayerChains []NetLayer
	Stopping    chan struct{}
	Session     Session

	tcpBuffer []byte
	Endpoint
}

func (client *Client) Connect(addr string, port int, login, password string, layersIndexes []uint8, defaultLayer uint8) bool {
	var err error
	if client.Session.Type() != "tcp" && client.Session.Type() != "udp" {
		log.Fatal().
			Str("state", "connecting").
			Str("connType", client.Session.Type()).
			Msg("Invalid connection type (only \"tcp\" or \"udp\")")
	}
	client.ServerAddr, err = NewAddress(client.Session.Type(), addr, port)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "connecting").
			Str("serverAddr", client.ServerAddr.String()).
			Msg("Failed to resolve server tcp address")
	}

	client.VirtualIP, err = client.Session.Open(client, defaultLayer, layersIndexes, login, password)
	if err != nil {
		log.Error().
			Err(err).
			Str("state", "listening").
			Str("serverAddr", client.ServerAddr.String()).
			Msg("Failed to connect to server")
		return false
	}

	log.Info().
		Str("state", "connecting").
		Str("connType", client.Session.Type()).
		Str("IP", client.VirtualIP.String()).
		Msg("Client connected to server")

	virtualIP4 := make(net.IP, len(*client.VirtualIP))
	copy(virtualIP4, *client.VirtualIP)
	virtualIP4[3] = 0
	gatewayIP4 := make(net.IP, len(*client.VirtualIP))
	copy(gatewayIP4, *client.VirtualIP)
	if (*client.VirtualIP)[3] != 1 {
		gatewayIP4[3] = 1
	} else {
		gatewayIP4[3] = 2
	}

	client.CIDR = fmt.Sprintf("%s/24", virtualIP4.String())
	client.Gateway = gatewayIP4.String()
	client.Tunnel = client.tunFactory(addr, client.CIDR, client.Gateway, client.Interface.Name(), client.WhiteList, client.BlackList)
	client.Tunnel.Stop() // clear broken routes
	err = client.Tunnel.Start(client.VirtualIP.String())

	if err != nil {
		return false
	}
	log.Info().
		Str("state", "connecting").
		Str("Net", client.CIDR).
		Msg("Tunnel created")

	return true
}

func (client *Client) ListenUnsafe() {
	defer log.Info().
		Str("state", "listening").
		Msg("Client disconnected")
	defer client.Session.Close()
	defer client.Tunnel.Stop()

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		<-c
		client.Stop("Ctrl+C pressed")
	}()

	localAddr, err := net.ResolveUDPAddr("udp", client.FullAddr)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "listening").
			Str("localAddr", client.FullAddr).
			Msg("Failed to resolve local address")
	}

	client.Conn, err = net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "listening").
			Str("localAddr", client.FullAddr).
			Msg("Failed to create a local server")
	}

	go funcSafe("Network=>Interface", func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-client.Stopping:
				return
			default:
			}

			n, err := client.Session.Read(buf)
			if err != nil || n == 0 {
				continue
			}
			packet, err := UnmarshalPacket(buf[:n])
			if err != nil {
				log.Debug().
					Err(err).
					Str("state", "N2I").
					Int("len", n).
					Int("addrType", int(packet.AddrType)).
					Msg("(Network=>Interface) Cannot unmarshal packet")
				continue
			}
			switch packet.AddrType {
			case 4:
				if !client.PacketAPI(client.Conn, client.ServerAddr, packet) {
					if _, err = client.Interface.Write(packet.Data); err != nil {
						log.Debug().
							Err(err).
							Str("state", "N2I").
							Int("len", n).
							Int("addrType", int(packet.AddrType)).
							Msg("(Network=>Interface) Cannot send packet")
					} else {
						log.Debug().
							Str("state", "N2I").
							Int("len", n).
							Int("addrType", int(packet.AddrType)).
							Msg("(Network=>Interface) Sent a packet")
					}
				} else {
					log.Debug().
						Int("len", n).
						Str("state", "N2I").
						Int("addrType", int(packet.AddrType)).
						Str("srcIP", packet.SrcIP.String()).
						Str("dstIP", packet.DstIP.String()).
						Msg("(Network=>Interface) Got API packet")
				}
			case 6:
				continue

			default:
				continue
			}
		}
	}, true)

	go funcSafe("Network<=Interface", func() {
		buffer := make([]byte, 1500)
		for {
			select {
			case <-client.Stopping:
				return
			default:
			}

			n, err := client.Interface.Read(buffer)
			if err != nil || n == 0 {
				continue
			}

			version := buffer[0] >> 4
			switch version {
			case 4:
				gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv4, gopacket.NoCopy)
				ip4 := gop.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

				if client.FilterIPs4(ip4) {
					packet, err := MakeDefaultPacket(ip4.SrcIP, ip4.DstIP, buffer[:n])
					if err != nil {
						log.Error().
							Err(err).
							Str("state", "I2N").
							Int("len", n).
							Str("srcIP", ip4.SrcIP.String()).
							Str("dstIP", ip4.DstIP.String()).
							Msg("(Network<=Interface) Failed to make a packet")
						continue
					}
					bytes, err := MarshalPacket(packet)
					if err != nil {
						log.Debug().
							Err(err).
							Str("state", "I2N").
							Int("len", n).
							Int("addrType", int(packet.AddrType)).
							Msg("(Network<=Interface) Failed to marshal packet")
						continue
					}
					if _, err = client.Session.Write(bytes); err != nil {
						log.Debug().
							Err(err).
							Str("state", "I2N").
							Int("len", n).
							Int("addrType", int(packet.AddrType)).
							Msg("(Network<=Interface) Failed to send packet")
					} else {
						log.Debug().
							Str("state", "I2N").
							Int("len", n).
							Int("addrType", int(packet.AddrType)).
							Msg("(Network<=Interface) Sent a packet")
					}
				}

			case 6:
				//gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv6, gopacket.NoCopy)
				//ip6 := gop.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				//log.Warn().
				//	Int("len", n).
				//	Str("state", "I2U").
				//	Int("addrType", int(version)).
				//	Msg("(Network<=Interface) IPv6 not supported")
				continue

			default:
				continue
			}
		}
	}, true)

	<-client.Stopping
	packet, err := MakeDisconnectPacket(client.ServerAddr.IP, client.IP)
	if err != nil {
		client.SendPacket(packet)
	}
}

func (client *Client) Listen() {
	funcSafe("mainLoop", client.ListenUnsafe, false)
}

func (client *Client) Stop(msg string) {
	select {
	case <-client.Stopping:
		return // already closed
	default:
		close(client.Stopping)
		log.Info().Str("state", "stopping").Msg(msg)
	}
}

func (client *Client) FilterIPs4(packet *layers.IPv4) bool {
	return !packet.DstIP.IsMulticast() && !packet.DstIP.IsLinkLocalUnicast() && !packet.DstIP.IsLoopback() &&
		!packet.DstIP.Equal(net.IPv4bcast) && !packet.DstIP.Equal(*client.VirtualIP) &&
		!packet.DstIP.Equal(client.Net.IP) && !isSubnetBroadcast(packet.DstIP, client.Net)
}
func isSubnetBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}

	return ip4.Equal(broadcast)
}
