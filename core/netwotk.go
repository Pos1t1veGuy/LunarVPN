package core

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
)

const MaxPayload = 1400
const ProtocolVersion byte = 1

// Packet [ProtocolVersion:1][PacketType:1][AddrType:1][SrcIP:4/16][DstIP:4/16][Rst:4][Length:2][Data:N]
type Packet struct {
	ProtocolVersion byte   // (1 - default version)
	Type            byte   // (0 - default data packet, 1 - api packet, 2 - keepalive)
	AddrType        byte   // (4 - IPv4, 6 - IPv6)
	SrcIP           net.IP // 4 or 16 bytes
	DstIP           net.IP // 4 or 16 bytes
	Rsv             [4]byte
	Length          uint16
	Data            []byte
}

func (packet *Packet) Len() int {
	return len(packet.Data)
}

func MarshalPacket(p *Packet) ([]byte, error) {
	buf := []byte{p.ProtocolVersion, p.Type, p.AddrType}

	if p.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version %d", p.ProtocolVersion)
	}

	if p.AddrType != 4 && p.AddrType != 6 {
		return nil, fmt.Errorf("invalid AddrType: %d", p.AddrType)
	}

	srcIPv, srcIP := validateIP(p.SrcIP)
	if srcIP == nil {
		return nil, fmt.Errorf("SrcIP is not valid IPv4: %v", p.SrcIP)
	}
	if srcIPv != p.AddrType {
		return nil, fmt.Errorf("invalid AddrType of srcIP: %d", p.AddrType)
	}
	dstIPv, dstIP := validateIP(p.DstIP)
	if dstIP == nil {
		return nil, fmt.Errorf("DstIP is not valid IPv4: %v", p.DstIP)
	}
	if dstIPv != p.AddrType {
		return nil, fmt.Errorf("invalid AddrType of dstIP: %d", p.AddrType)
	}

	if len(p.Data) > math.MaxUint16 {
		return nil, fmt.Errorf("packet Data too large: %d bytes", len(p.Data))
	}
	buf = append(buf, srcIP...)
	buf = append(buf, dstIP...)
	buf = append(buf, p.Rsv[:]...)

	if int(p.Length) != len(p.Data) {
		return nil, fmt.Errorf(
			"packet length mismatch: header=%d actual=%d",
			p.Length,
			len(p.Data),
		)
	}

	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, p.Length)
	buf = append(buf, lengthBytes...)
	buf = append(buf, p.Data...)

	return buf, nil
}
func UnmarshalPacket(data []byte) (*Packet, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("too short")
	}

	p := &Packet{
		ProtocolVersion: data[0],
		Type:            data[1],
		AddrType:        data[2],
	}

	if p.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version %d", p.ProtocolVersion)
	}

	var ipLen int
	switch p.AddrType {
	case 4:
		ipLen = 4
	case 6:
		ipLen = 16
	default:
		return nil, fmt.Errorf("invalid AddrType: %d", p.AddrType)
	}

	headerLen := 3 + ipLen*2 + 4 + 2
	if len(data) < headerLen {
		return nil, fmt.Errorf(
			"packet too short for AddrType %d: %d < %d",
			p.AddrType, len(data), headerLen,
		)
	}

	offset := 3
	p.SrcIP = net.IP(append([]byte(nil), data[offset:offset+ipLen]...))
	offset += ipLen
	p.DstIP = net.IP(append([]byte(nil), data[offset:offset+ipLen]...))
	offset += ipLen

	copy(p.Rsv[:], data[offset:offset+4])
	offset += 4

	p.Length = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	payloadLen := len(data) - offset
	if int(p.Length) != payloadLen {
		return nil, fmt.Errorf(
			"payload length mismatch: header=%d actual=%d",
			p.Length, payloadLen,
		)
	}

	p.Data = append([]byte(nil), data[offset:]...)

	return p, nil
}

func MakeDefaultPacket(srcAddr net.IP, dstAddr net.IP, data []byte) (*Packet, error) {
	srcIPv, srcIP := validateIP(srcAddr)
	dstIPv, dstIP := validateIP(dstAddr)

	if srcIP == nil {
		return nil, fmt.Errorf("srcIP is not valid IPv%d: %v", srcIPv, srcIP)
	}
	if dstIP == nil {
		return nil, fmt.Errorf("dsrIP is not valid IPv%d: %v", dstIPv, srcIP)
	}
	if srcIPv != dstIPv {
		return nil, fmt.Errorf("IP version mismatch: src=%d, dst=%d", srcIPv, dstIPv)
	}

	return &Packet{
		ProtocolVersion: ProtocolVersion,
		Type:            0,
		AddrType:        srcIPv,
		SrcIP:           srcIP,
		DstIP:           dstIP,
		Rsv:             [4]byte{0, 0, 0, 0},
		Length:          uint16(len(data)),
		Data:            data,
	}, nil
}

func MakeDisconnectPacket(serverAddr net.IP, clientAddr net.IP) (*Packet, error) {
	srcIPv, srcIP := validateIP(serverAddr)
	dstIPv, dstIP := validateIP(clientAddr)

	if srcIP == nil {
		return nil, fmt.Errorf("srcIP is not valid IPv%d: %v", srcIPv, srcIP)
	}
	if dstIP == nil {
		return nil, fmt.Errorf("dsrIP is not valid IPv%d: %v", dstIPv, srcIP)
	}
	if srcIPv != dstIPv {
		return nil, fmt.Errorf("IP version mismatch: src=%d, dst=%d", srcIPv, dstIPv)
	}

	return &Packet{
		ProtocolVersion: ProtocolVersion,
		Type:            1,
		AddrType:        srcIPv,
		SrcIP:           srcIP,
		DstIP:           dstIP,
		Rsv:             [4]byte{0, 0, 0, 0},
		Length:          0,
		Data:            nil,
	}, nil
}

func MakePingPacket(srcIP net.IP, dstIP net.IP) (*Packet, error) {
	srcIPv, srcIP := validateIP(srcIP)
	dstIPv, dstIP := validateIP(dstIP)

	if srcIP == nil {
		return nil, fmt.Errorf("srcIP is not valid IPv%d: %v", srcIPv, srcIP)
	}
	if dstIP == nil {
		return nil, fmt.Errorf("dsrIP is not valid IPv%d: %v", dstIPv, srcIP)
	}
	if srcIPv != dstIPv {
		return nil, fmt.Errorf("IP version mismatch: src=%d, dst=%d", srcIPv, dstIPv)
	}

	return &Packet{
		ProtocolVersion: ProtocolVersion,
		Type:            1,
		AddrType:        srcIPv,
		SrcIP:           srcIP,
		DstIP:           dstIP,
		Rsv:             [4]byte{0, 0, 0, 1},
		Length:          0,
		Data:            nil,
	}, nil
}

func (client *Client) SendPacket(packet *Packet) {
	bytes, err := MarshalPacket(packet)
	if err != nil {
		log.Debug().
			Err(err).
			Str("state", "serverCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(UDP<=Interface) Failed to marshal packet")
	}

	if _, err = client.Session.Write(bytes); err != nil {
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

func (server *Server) SendPacket(packet *Packet, peerAddr *net.UDPAddr, layer NetLayer) {
	bytes, err := MarshalPacket(packet)
	if err != nil {
		log.Debug().
			Err(err).
			Str("state", "clientCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(UDP<=Interface) Failed to marshal packet")
	}

	wrapped, err := layer.Wrap(bytes)
	if err != nil {
		log.Debug().
			Err(err).
			Str("state", "clientCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(UDP<=Interface) Failed to wrap packet")
	}

	if _, err = server.Conn.WriteToUDP(wrapped, peerAddr); err != nil {
		log.Debug().
			Err(err).
			Str("state", "clientCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(UDP<=Interface) Failed to send packet")
	} else {
		log.Debug().
			Str("state", "clientCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(UDP<=Interface) Sent a packet")
	}
}

func (server *Server) PacketAPI(conn net.UDPConn, peer *Peer, packet *Packet, clientAddr *net.UDPAddr) bool {
	if packet.Type == 1 {
		strClientAddr := peer.Addr.String()

		switch packet.Rsv {
		case [4]byte{0, 0, 0, 0}: // disconnect
			if _, exists := server.Peers[strClientAddr]; exists {
				server.mu.Lock()
				delete(server.Peers, strClientAddr)
				server.mu.Unlock()
				log.Info().
					Str("state", "API").
					Str("peer", strClientAddr).
					Str("localIP", packet.SrcIP.String()).
					Msg("(UDP=>Interface) Peer disconnected")
			} else {
				log.Info().
					Str("state", "API").
					Str("peer", strClientAddr).
					Str("localIP", packet.SrcIP.String()).
					Msg("(UDP=>Interface) Peer not found")
			}

		case [4]byte{0, 0, 0, 1}: // ping
			ping, err := MakePingPacket(server.IP, peer.Addr.IP)
			if err != nil {
				log.Error().
					Err(err).
					Str("state", "API").
					Str("peer", strClientAddr).
					Str("localIP", packet.SrcIP.String()).
					Msg("(UDP=>Interface) Failed to make a PING packet")
				return true
			}
			server.SendPacket(ping, peer.Addr, peer.NLChain)
		}

		server.Cache.Set(
			clientAddr.String(),
			peer,
			cache.DefaultExpiration,
		)

		return true
	}
	return false
}

func (client *Client) PacketAPI(conn net.UDPConn, serverAddr net.UDPAddr, packet *Packet) bool {
	if packet.Type == 1 {
		switch packet.Rsv {
		case [4]byte{0, 0, 0, 0}: // disconnect
			client.Stop("(UDP=>Interface) Server disconnected you")
		case [4]byte{0, 0, 0, 1}: // pong
			ping := client.Session.GetPing()
			ping.Calculate()
			log.Info().
				Str("state", "API").
				Str("ping", ping.Value.Truncate(time.Millisecond).String()).
				Msg("(UDP=>Interface) Pong received")
		}
		return true
	}
	return false
}

type Ping struct {
	TimeStart  time.Time
	Calculated bool
	Value      time.Duration
	Duration   time.Duration
	Response   bool

	mu sync.Mutex
}

func NewPing(dur time.Duration) *Ping {
	return &Ping{Duration: dur, Response: true}
}
func (ping *Ping) Start() {
	ping.mu.Lock()
	ping.Calculated = false
	ping.TimeStart = time.Now()
	ping.Value = 0 * time.Second
	ping.mu.Unlock()

	go func() {
		timer := time.NewTimer(ping.Duration)
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
