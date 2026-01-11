package core

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

func (client *Client) Handshake() (net.IP, error) {
	packet, err := MakeDefaultPacket(net.ParseIP("0.0.0.0"), client.ServerAddr.IP, []byte{0x01, 0x01})
	if err != nil {
		return nil, err
	}
	clientHello, err := MarshalPacket(packet)

	if err != nil {
		return nil, err
	}

	_, err = client.serverConn.Write(clientHello)

	if err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)

	for {
		n, err := client.serverConn.Read(buf)
		if err != nil {
			return nil, err
		}
		packet, err := UnmarshalPacket(buf[:n])
		if err != nil {
			return nil, err
		}

		if packet.Len() < 2 {
			continue
		}

		if packet.Data[0] != 0x02 || packet.Data[1] != 0x00 {
			continue
		}

		if packet.DstIP.Equal(net.IPv4zero) {
			return nil, errors.New("server returned zero IP")
		}

		return packet.DstIP, nil
	}
}

func (server *Server) Handshake(n int, buf []byte, addr *net.UDPAddr) (*Peer, error) {
	packet, err := UnmarshalPacket(buf[:n])
	if err != nil {
		return nil, err
	}

	if packet.Len() >= 2 && packet.Data[0] == 0x01 && packet.Data[1] == 0x01 {
		virtualIP, err := server.Network.Next()
		if err != nil {
			return server.AnonymousPeer, fmt.Errorf("get next virtual ip failed: %v", err)
		}

		packetResp, err := MakeDefaultPacket(server.IP, virtualIP, []byte{0x02, 0x00})
		if err != nil {
			return server.AnonymousPeer, fmt.Errorf("can not make a new packet: %v", err)
		}
		resp, err := MarshalPacket(packetResp)
		if err != nil {
			return server.AnonymousPeer, fmt.Errorf("marshal packet failed: %v", err)
		}
		_, err = server.Conn.WriteToUDP(resp, addr)
		if err != nil {
			return server.AnonymousPeer, fmt.Errorf("handshake response error: %v", err)
		}

		server.mu.Lock()
		server.Peers[addr.String()] = NewPeer(virtualIP, addr, true)
		server.mu.Unlock()

		return server.Peers[addr.String()], nil
	}
	return server.AnonymousPeer, errors.New("not a handshake")
}

func (server *Server) PacketAPI(conn net.UDPConn, clientAddr net.UDPAddr, packet *Packet) bool {
	if packet.Type == 1 {
		strClientAddr := clientAddr.String()

		switch packet.Rsv {
		case [4]byte{0, 0, 0, 0}: // disconnect
			server.mu.Lock()
			if _, exists := server.Peers[strClientAddr]; exists {
				delete(server.Peers, strClientAddr)
				log.Info().
					Str("state", "API").
					Str("peer", strClientAddr).
					Str("localIP", packet.SrcIP.String()).
					Msg("Peer disconnected")
			} else {
				log.Info().
					Str("state", "API").
					Str("peer", strClientAddr).
					Str("localIP", packet.SrcIP.String()).
					Msg("Peer not found")
			}
			server.mu.Unlock()

		case [4]byte{0, 0, 0, 1}: // ping
			packet, err := MakePingPacket(server.IP, clientAddr.IP)
			if err != nil {
				log.Error().
					Err(err).
					Str("state", "API").
					Str("peer", strClientAddr).
					Str("localIP", packet.SrcIP.String()).
					Msg("Failed to make a PING packet")
				return true
			}
			bytes, err := MarshalPacket(packet)
			if err != nil {
				log.Debug().
					Err(err).
					Str("state", "API").
					Str("dstAddr", strClientAddr).
					Msg("Failed to marshal packet")
			}
			if _, err := conn.WriteToUDP(bytes, &clientAddr); err != nil {
				log.Debug().
					Err(err).
					Str("state", "API").
					Str("dstAddr", strClientAddr).
					Msg("Failed to send packet")
			} else {
				log.Debug().
					Str("state", "API").
					Str("dstAddr", strClientAddr).
					Msg("Sent a packet")
			}
		}
		return true
	}
	return false
}

func (client *Client) PacketAPI(conn net.UDPConn, serverAddr net.UDPAddr, packet *Packet) bool {
	if packet.Type == 1 {
		switch packet.Rsv {
		case [4]byte{0, 0, 0, 0}: // disconnect
			client.Stop("Server disconnected you")
		case [4]byte{0, 0, 0, 1}: // pong
			client.Ping.Calculate()
			log.Info().
				Str("state", "API").
				Str("ping", client.Ping.Value.Truncate(time.Millisecond).String()).
				Msg("Pong received")
		}
		return true
	}
	return false
}

type Ping struct {
	TimeStart  time.Time
	Calculated bool
	Value      time.Duration
	Threshold  time.Duration
	Response   bool

	mu sync.Mutex
}

func NewPing(threshold time.Duration) *Ping {
	return &Ping{Threshold: threshold, Response: true}
}
func (ping *Ping) Start() {
	ping.mu.Lock()
	ping.Calculated = false
	ping.TimeStart = time.Now()
	ping.Value = 0 * time.Second
	ping.mu.Unlock()

	go func() {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()

		<-timer.C

		ping.mu.Lock()
		defer ping.mu.Unlock()

		if !ping.Calculated {
			ping.Response = false
		}
	}()
}
func (ping *Ping) Calculate() time.Duration {
	ping.mu.Lock()
	defer ping.mu.Unlock()
	ping.Calculated = true
	ping.Value = time.Since(ping.TimeStart)
	ping.Response = true
	return ping.Value
}

func validateIP(ip net.IP) (byte, net.IP) {
	ip4 := ip.To4()
	if ip4 != nil {
		return 4, ip4
	}
	ip16 := ip.To16()
	if ip16 != nil {
		return 6, ip16
	}
	return 0, nil
}
