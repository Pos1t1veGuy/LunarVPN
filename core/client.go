package core

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

type Client struct {
	ServerAddr *net.UDPAddr
	VirtualIP  net.IP
	serverConn *net.UDPConn
	WhiteList  []string
	Interface  InterfaceAdapter
	Stopping   chan struct{}

	Ping *Ping
	Endpoint
}

func (client *Client) Connect(addr string, port int) bool {
	var err error
	serverAddrFormatted := fmt.Sprintf("%s:%d", addr, port)
	client.ServerAddr, err = net.ResolveUDPAddr("udp", serverAddrFormatted)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "connecting").
			Str("serverAddr", serverAddrFormatted).
			Msg("Failed to resolve server address")
	}

	client.serverConn, err = net.DialUDP("udp", nil, client.ServerAddr)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "listening").
			Str("serverAddr", client.ServerAddr.String()).
			Msg("Failed to connect to server")
	}

	log.Info().Str("ServerAddr", serverAddrFormatted).Msg("Connecting")
	client.VirtualIP, err = client.Handshake()
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "connecting").
			Str("serverAddr", serverAddrFormatted).
			Msg("Failed to handshake client")
	}
	log.Debug().
		Str("state", "connecting").
		Str("IP", client.VirtualIP.String()).
		Msg("Client connected to server")

	err = ConfigTunnel(addr, client.CIDR, client.VirtualIP.String(), client.Interface.Name(), client.WhiteList)
	if err != nil {
		return false
	}
	log.Info().
		Str("state", "connecting").
		Str("Net", client.CIDR).
		Msg("Tunnel created")

	return true
}

func (client *Client) Listen() {
	defer log.Info().Msg("Client disconnected")
	defer client.serverConn.Close()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

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
	defer client.Conn.Close()

	go client.PingLoop(10 * time.Second)

	// udp => interface
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := client.serverConn.Read(buf)
			if err != nil || n == 0 {
				continue
			}

			packet, err := UnmarshalPacket(buf[:n])
			if err != nil || packet.AddrType != 4 {
				log.Debug().
					Err(err).
					Str("state", "U2I").
					Int("len", n).
					Int("AddrType", int(packet.AddrType)).
					Msg("(UDP=>Interface) Cannot unmarshal packet")
				continue
			}
			if !client.PacketAPI(*client.Conn, *client.ServerAddr, packet) {
				if _, err = client.Interface.Write(packet.Data); err != nil {
					log.Debug().
						Err(err).
						Str("state", "U2I").
						Int("len", n).
						Int("AddrType", int(packet.AddrType)).
						Msg("(UDP=>Interface) Cannot send packet")
				} else {
					log.Debug().
						Str("state", "U2I").
						Int("len", n).
						Int("AddrType", int(packet.AddrType)).
						Msg("(UDP=>Interface) Sent a packet")
				}
			} else {
				log.Debug().
					Int("len", n).
					Str("state", "U2I").
					Int("addrType", int(packet.AddrType)).
					Str("srcIP", packet.SrcIP.String()).
					Str("dstIP", packet.DstIP.String()).
					Msg("(UDP=>Interface) Got API packet")
			}
		}
	}()

	// interface => udp
	go func() {
		buffer := make([]byte, 1500)
		for {
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
					packet := Packet{
						Type:     0,
						AddrType: 4,
						SrcIP:    ip4.SrcIP,
						DstIP:    ip4.DstIP,
						Rsv:      [4]byte{0, 0, 0, 0},
						Length:   uint16(n),
						Data:     buffer[:n],
					}
					bytes, err := MarshalPacket(&packet)
					if err != nil {
						log.Debug().
							Err(err).
							Str("state", "I2U").
							Int("len", n).
							Int("AddrType", int(packet.AddrType)).
							Msg("(UDP<=Interface) Failed to marshal packet")
						continue
					}
					if _, err = client.serverConn.Write(bytes); err != nil {
						log.Debug().
							Err(err).
							Str("state", "I2U").
							Int("len", n).
							Int("AddrType", int(packet.AddrType)).
							Msg("(UDP<=Interface) Failed to send packet")
					} else {
						log.Debug().
							Str("state", "I2U").
							Int("len", n).
							Int("AddrType", int(packet.AddrType)).
							Msg("(UDP<=Interface) Sent a packet")
					}
				}

			case 6:
				//gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv6, gopacket.NoCopy)
				//ip6 := gop.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				//log.Warn().
				//	Int("len", n).
				//	Str("state", "I2U").
				//	Int("AddrType", int(version)).
				//	Msg("(UDP<=Interface) IPv6 not supported")
				continue

			default:
				continue
			}
		}
	}()

	<-sigs // waiting for Ctrl+C
	SendPacket(client.serverConn, MakeDisconnectPacket(client.ServerAddr.IP, client.IP))
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

func (client *Client) PingLoop(duration time.Duration) {
	packet := MakePingPacket(client.IP, client.ServerAddr.IP)
	for {
		SendPacket(client.serverConn, packet)
		if client.Ping.Calculated {
			client.Ping.Start()
		}
		time.Sleep(duration)
	}
}

func (client *Client) FilterIPs4(packet *layers.IPv4) bool {
	return !packet.DstIP.IsMulticast() && !packet.DstIP.IsLinkLocalUnicast() && !packet.DstIP.IsLoopback() &&
		!packet.DstIP.Equal(net.IPv4bcast) && !packet.DstIP.Equal(client.VirtualIP) &&
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
