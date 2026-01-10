package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

func (client *Client) Handshake() (net.IP, error) {
	_, err := client.serverConn.Write([]byte{0x01, 0x01})

	if err != nil {
		return nil, fmt.Errorf("udp send error: %v", err)
	}

	buf := make([]byte, 1024)

	for {
		n, err := client.serverConn.Read(buf)
		if err != nil {
			return net.IP(buf[2:6]), fmt.Errorf("udp read error: %v", err)
		}

		if n < 6 {
			continue
		}

		if buf[0] != 0x02 || buf[1] != 0x00 {
			continue
		}

		ip := net.IP(buf[2:6])
		if ip.Equal(net.IPv4zero) {
			return nil, errors.New("server returned zero IP")
		}

		return ip, nil
	}
}

func (server *Server) Handshake(n int, buf []byte, addr *net.UDPAddr) (*Peer, error) {
	if n >= 2 && buf[0] == 0x01 && buf[1] == 0x01 {
		virtualIP, err := server.Network.Next()
		if err != nil {
			return server.AnonymousPeer, fmt.Errorf("get next virtual ip failed: %v", err)
		}

		resp := append([]byte{0x02, 0x00}, virtualIP.To4()...)
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

// [PacketType:1][AddrType:1][SrcIP:4/16][DstIP:4/16][Rst:4][Length:2][Data:N]
type Packet struct {
	Type     byte   // (0 - default data packet, 1 - api packet, 2 - keepalive)
	AddrType byte   // (4 - IPv4, 6 - IPv6)
	SrcIP    net.IP // 4 or 16 bytes
	DstIP    net.IP // 4 or 16 bytes
	Rsv      [4]byte
	Length   uint16
	Data     []byte
}

func MarshalPacket(p *Packet) ([]byte, error) {
	buf := []byte{p.Type, p.AddrType}

	if p.AddrType == 4 {
		buf = append(buf, p.SrcIP.To4()...)
		buf = append(buf, p.DstIP.To4()...)
	} else if p.AddrType == 6 {
		buf = append(buf, p.SrcIP.To16()...)
		buf = append(buf, p.DstIP.To16()...)
	} else {
		return nil, fmt.Errorf("unknown address type: %v", p.AddrType)
	}
	buf = append(buf, p.Rsv[:]...)

	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, p.Length)
	buf = append(buf, lengthBytes...)

	buf = append(buf, p.Data...)

	return buf, nil
}
func UnmarshalPacket(data []byte) (*Packet, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("too short")
	}

	p := &Packet{
		Type:     data[0],
		AddrType: data[1],
	}

	ipLen := 4
	if p.AddrType == 6 {
		ipLen = 16
	}

	offset := 2
	p.SrcIP = net.IP(data[offset : offset+ipLen])
	offset += ipLen
	p.DstIP = net.IP(data[offset : offset+ipLen])
	offset += ipLen

	copy(p.Rsv[:], data[offset:offset+4])
	offset += 4

	p.Length = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	p.Data = data[offset:]

	return p, nil
}

func SendPacket(conn *net.UDPConn, packet *Packet) {
	bytes, err := MarshalPacket(packet)
	if err != nil {
		log.Debug().
			Err(err).
			Str("state", "serverCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(UDP<=Interface) Failed to marshal packet")
	}
	if _, err = conn.Write(bytes); err != nil {
		log.Debug().
			Err(err).
			Str("state", "serverCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(UDP<=Interface) Failed to send packet")
	} else {
		log.Debug().
			Str("state", "serverCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(UDP<=Interface) Sent a packet")
	}
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
			bytes, err := MarshalPacket(MakePingPacket(server.IP, clientAddr.IP))
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
		}
		return true
	}
	return false
}

func MakeDisconnectPacket(serverAddr net.IP, clientAddr net.IP) *Packet {
	var version int
	if serverAddr.To4() != nil {
		version = 4
	} else {
		version = 6
	}
	return &Packet{
		Type:     1,
		AddrType: byte(version),
		SrcIP:    clientAddr,
		DstIP:    serverAddr,
		Rsv:      [4]byte{0, 0, 0, 0},
		Length:   0,
		Data:     nil,
	}
}

func MakePingPacket(srcIP net.IP, dstIP net.IP) *Packet {
	var version int
	if dstIP.To4() != nil {
		version = 4
	} else {
		version = 6
	}
	return &Packet{
		Type:     1,
		AddrType: byte(version),
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Rsv:      [4]byte{0, 0, 0, 1},
		Length:   0,
		Data:     nil,
	}
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
	return &Ping{Threshold: threshold}
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
	return ping.Value
}
