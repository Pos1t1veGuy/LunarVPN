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
	ServerAddr   *net.UDPAddr
	VirtualIP    net.IP
	serverConn   *net.UDPConn
	WhiteList    []string
	BlackList    []string
	Interface    InterfaceAdapter
	Tunnel       *Tunnel
	ActiveNLayer NetLayer
	LayerChains  []NetLayer
	Stopping     chan struct{}

	Ping *Ping
	Endpoint
}

func (client *Client) Connect(addr string, port int, login, password string, layersIndexes []uint8, defaultLayer uint8) bool {
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
		log.Error().
			Err(err).
			Str("state", "listening").
			Str("serverAddr", client.ServerAddr.String()).
			Msg("Failed to connect to server")
		return false
	}

	log.Info().
		Str("state", "connecting").
		Str("ServerAddr", serverAddrFormatted).
		Str("login", login).
		Msg("Connecting")

	_ = client.serverConn.SetDeadline(time.Now().Add(3 * time.Second))
	var virtualIP net.IP
	for attempt := 1; attempt <= 3; attempt++ {
		virtualIP, client.ActiveNLayer, err = client.Handshake(
			layersIndexes,
			[]byte(fmt.Sprintf("%s:%s", login, password)),
			defaultLayer,
		)
		if err == nil {
			break
		}
		log.Warn().
			Err(err).
			Str("state", "connecting").
			Int("attempt", attempt).
			Msg("Handshake failed, retrying...")
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.Error().
			Str("state", "connecting").
			Msg("All handshake attempts failed. Server is unavailable")
		return false
	}
	client.VirtualIP = virtualIP
	_ = client.serverConn.SetDeadline(time.Time{})
	log.Info().
		Str("state", "connecting").
		Str("IP", client.VirtualIP.String()).
		Msg("Client connected to server")

	virtualIP4 := make(net.IP, len(client.VirtualIP))
	copy(virtualIP4, client.VirtualIP)
	virtualIP4[3] = 0

	client.CIDR = fmt.Sprintf("%s/24", virtualIP4.String())
	client.Tunnel = NewTunnel(addr, client.CIDR, client.Interface.Name(), client.WhiteList, client.BlackList)
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
	defer client.serverConn.Close()
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
	defer client.Conn.Close()

	go client.PingLoop(5 * time.Second)

	go funcSafe("UDP=>Interface", func() {
		buf := make([]byte, 1500)
		for {
			select {
			case <-client.Stopping:
				return
			default:
			}

			n, err := client.serverConn.Read(buf)
			if err != nil || n == 0 {
				time.Sleep(5 * time.Millisecond)
				continue
			}

			unwrapped, err := client.ActiveNLayer.Unwrap(buf[:n])
			if err != nil {
				log.Error().
					Err(err).
					Str("state", "U2I").
					Int("len", n).
					Msg("(UDP=>Interface) Failed to unwrap packet")
				time.Sleep(5 * time.Millisecond)
				continue
			}
			packet, err := UnmarshalPacket(unwrapped)
			if err != nil {
				log.Debug().
					Err(err).
					Str("state", "U2I").
					Int("len", n).
					Int("addrType", int(packet.AddrType)).
					Msg("(UDP=>Interface) Cannot unmarshal packet")
				time.Sleep(5 * time.Millisecond)
				continue
			}
			switch packet.AddrType {
			case 4:
				if !client.PacketAPI(*client.Conn, *client.ServerAddr, packet) {
					if _, err = client.Interface.Write(packet.Data); err != nil {
						log.Debug().
							Err(err).
							Str("state", "U2I").
							Int("len", n).
							Int("addrType", int(packet.AddrType)).
							Msg("(UDP=>Interface) Cannot send packet")
					} else {
						log.Debug().
							Str("state", "U2I").
							Int("len", n).
							Int("addrType", int(packet.AddrType)).
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
			case 6:
				time.Sleep(5 * time.Millisecond)
				continue

			default:
				time.Sleep(5 * time.Millisecond)
				continue
			}
			time.Sleep(5 * time.Millisecond)
		}
	}, true)

	go funcSafe("UDP<=Interface", func() {
		buffer := make([]byte, 1500)
		for {
			select {
			case <-client.Stopping:
				return
			default:
			}

			n, err := client.Interface.Read(buffer)
			if err != nil || n == 0 {
				time.Sleep(5 * time.Millisecond)
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
							Str("state", "I2U").
							Int("len", n).
							Str("srcIP", ip4.SrcIP.String()).
							Str("dstIP", ip4.DstIP.String()).
							Msg("(UDP<=Interface) Failed to make a packet")
						time.Sleep(5 * time.Millisecond)
						continue
					}
					bytes, err := MarshalPacket(packet)
					if err != nil {
						log.Debug().
							Err(err).
							Str("state", "I2U").
							Int("len", n).
							Int("addrType", int(packet.AddrType)).
							Msg("(UDP<=Interface) Failed to marshal packet")
						time.Sleep(5 * time.Millisecond)
						continue
					}
					wrapped, err := client.ActiveNLayer.Wrap(bytes)
					if _, err = client.serverConn.Write(wrapped); err != nil {
						log.Debug().
							Err(err).
							Str("state", "I2U").
							Int("len", n).
							Int("addrType", int(packet.AddrType)).
							Msg("(UDP<=Interface) Failed to send packet")
					} else {
						log.Debug().
							Str("state", "I2U").
							Int("len", n).
							Int("addrType", int(packet.AddrType)).
							Msg("(UDP<=Interface) Sent a packet")
					}
				}

			case 6:
				//gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv6, gopacket.NoCopy)
				//ip6 := gop.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				//log.Warn().
				//	Int("len", n).
				//	Str("state", "I2U").
				//	Int("addrType", int(version)).
				//	Msg("(UDP<=Interface) IPv6 not supported")
				time.Sleep(5 * time.Millisecond)
				continue

			default:
				time.Sleep(5 * time.Millisecond)
				continue
			}
			time.Sleep(5 * time.Millisecond)
		}
	}, true)

	<-client.Stopping
	packet, err := MakeDisconnectPacket(client.ServerAddr.IP, client.IP)
	if err != nil {
		client.SendPacket(packet, client.ActiveNLayer)
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

func (client *Client) PingLoop(duration time.Duration) {
	packet, err := MakePingPacket(client.VirtualIP, client.ServerAddr.IP)
	if err != nil {
		log.Error().
			Err(err).
			Str("state", "ping").
			Msg("Failed to make a PING packet. Ping loop is disabled")
		return
	}
	attempts := 0

	for {
		select {
		case <-client.Stopping:
			return
		default:
		}

		client.Ping.Start()
		client.SendPacket(packet, client.ActiveNLayer)
		log.Debug().
			Str("state", "ping").
			Msg("Ping server")

		time.Sleep(duration)

		if !client.Ping.Response {
			if attempts < 3 {
				attempts++
				log.Error().
					Str("state", "ping").
					Int("try", attempts).
					Msg("Server did not respond to ping request")
			} else {
				log.Error().
					Str("state", "ping").
					Int("try", attempts).
					Msg("Server did not respond to ping request. Closing connection")
				client.Stop("Server stopped responding")
				return
			}
		} else {
			attempts = 0
		}
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
