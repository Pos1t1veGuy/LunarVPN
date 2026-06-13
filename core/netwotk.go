package core

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const MaxPayload = 1360
const ProtocolVersion byte = 1
const HeaderIPv4Length = 3 + 4 + 4 + 4 + 2
const HeaderIPv6Length = 3 + 16 + 16 + 4 + 2

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
		return nil, fmt.Errorf("packet length mismatch: header=%d actual=%d", p.Length, len(p.Data))
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

type ProcessBufferResult struct {
	CompletePacket []byte
	RemainingBuf   []byte
	Err            error
}

func ExtractPacket(buf []byte) (bool, *ProcessBufferResult) {
	result := &ProcessBufferResult{}

	if len(buf) < 3 {
		return false, nil
	}

	addrType := buf[2]

	var headerLen int
	switch addrType {
	case 4:
		headerLen = HeaderIPv4Length
	case 6:
		headerLen = HeaderIPv6Length
	default:
		result.Err = fmt.Errorf("invalid AddrType %d in stream", addrType)
		return true, result
	}

	if len(buf) < headerLen {
		return false, nil
	}

	payloadLen := binary.BigEndian.Uint16(buf[headerLen-2 : headerLen])
	totalLen := headerLen + int(payloadLen)

	if totalLen > 10*1024*1024 {
		result.Err = fmt.Errorf("packet too large: %d bytes", totalLen)
		return true, result
	}

	if len(buf) < totalLen {
		return false, nil // Ждем еще данных
	}

	result.CompletePacket = buf[:totalLen]
	result.RemainingBuf = buf[totalLen:]

	return true, result
}

func MakeDefaultPacket(srcAddr net.IP, dstAddr net.IP, data []byte) (*Packet, error) {
	srcIPv, srcIP := validateIP(srcAddr)
	dstIPv, dstIP := validateIP(dstAddr)

	if srcIP == nil {
		return nil, fmt.Errorf("srcIP is not valid 'IPv%d': %v", srcIPv, srcIP)
	}
	if dstIP == nil {
		return nil, fmt.Errorf("dstIP is not valid 'IPv%d': %v", dstIPv, srcIP)
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
			Msg("(Network<=Interface) Failed to marshal packet")
	}

	if _, err = client.Session.Write(bytes); err != nil {
		log.Debug().
			Err(err).
			Str("state", "serverCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(Network<=Interface) Failed to send packet")
	} else {
		log.Debug().
			Str("state", "serverCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(Network<=Interface) Sent a packet")
	}
}

func (server *Server) SendPacket(packet *Packet, peer *Peer) {
	bytes, err := MarshalPacket(packet)
	if err != nil {
		log.Debug().
			Err(err).
			Str("state", "clientCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(Network<=Interface) Failed to marshal packet")
		return
	}

	wrapped, err := peer.NLChain.Wrap(bytes)
	if err != nil {
		log.Debug().
			Err(err).
			Str("state", "clientCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(Network<=Interface) Failed to wrap packet")
		return
	}

	writeToPeer := func() (int, error) { return server.Conn.WriteToUDP(wrapped, peer.Addr.UdpParent) }
	if peer.Addr.Type == "tcp" {
		writeToPeer = func() (int, error) { return peer.TcpWrite(wrapped) }
	}

	if _, err = writeToPeer(); err != nil {
		log.Debug().
			Err(err).
			Str("state", "clientCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(Network<=Interface) Failed to send packet")
	} else {
		log.Debug().
			Str("state", "clientCommand").
			Int("len", len(bytes)).
			Int("AddrType", int(packet.AddrType)).
			Msg("(Network<=Interface) Sent a packet")
	}
}

func (server *Server) PacketAPI(conn net.Conn, peer *Peer, packet *Packet) bool {
	if packet.Type == 1 {
		strClientAddr := peer.Addr.String()

		switch packet.Rsv {
		case [4]byte{0, 0, 0, 0}: // disconnect
			if _, exists := server.Peers[strClientAddr]; exists {
				_ = server.DisconnectPeer(peer)
				log.Info().
					Str("state", "API").
					Str("peer", strClientAddr).
					Str("connType", peer.Addr.Type).
					Str("localIP", packet.SrcIP.String()).
					Msg("(Network=>Interface) Peer disconnected")
			} else {
				log.Info().
					Str("state", "API").
					Str("peer", strClientAddr).
					Str("connType", peer.Addr.Type).
					Str("localIP", packet.SrcIP.String()).
					Msg("(Network=>Interface) Peer not found")
			}

		case [4]byte{0, 0, 0, 1}: // ping
			ping, err := MakePingPacket(server.IP, peer.Addr.IP)
			if err != nil {
				log.Error().
					Err(err).
					Str("state", "API").
					Str("peer", strClientAddr).
					Str("connType", peer.Addr.Type).
					Str("localIP", packet.SrcIP.String()).
					Msg("(Network=>Interface) Failed to make a PING packet")
				return true
			}
			server.SendPacket(ping, peer)
		}
		return true
	}
	return false
}

func (client *Client) PacketAPI(conn net.Conn, serverAddr *Address, packet *Packet) bool {
	if packet.Type == 1 {
		switch packet.Rsv {
		case [4]byte{0, 0, 0, 0}: // disconnect
			client.Stop("(Network=>Interface) Server disconnected you")
		case [4]byte{0, 0, 0, 1}: // pong
		}
		return true
	}
	return false
}

type Ping interface {
	Start()
	Calculate() time.Duration
	GetValue() time.Duration
	GetResponse() bool
}

type DefaultPing struct {
	TimeStart  time.Time
	Calculated bool
	Value      time.Duration
	Duration   time.Duration
	Response   bool

	mu sync.Mutex
}

func NewDefaultPing(dur time.Duration) *DefaultPing {
	return &DefaultPing{Duration: dur, Response: true}
}
func (ping *DefaultPing) GetValue() time.Duration {
	return ping.Value
}
func (ping *DefaultPing) GetResponse() bool {
	return ping.Response
}
func (ping *DefaultPing) Start() {
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
func (ping *DefaultPing) Calculate() time.Duration {
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

type Address struct {
	Type string // "udp" or "tcp"
	IP   net.IP
	Port int
	Zone string

	UdpParent *net.UDPAddr
	TcpParent *net.TCPAddr

	addrString string
}

func NewAddress(connType, ip string, port int) (*Address, error) {
	addrFormatted := fmt.Sprintf("%s:%d", ip, port)
	parentTcpAddr, err := net.ResolveTCPAddr("tcp", addrFormatted)
	if err != nil {
		return nil, err
	}
	parentUdpAddr, err := net.ResolveUDPAddr("udp", addrFormatted)
	if err != nil {
		return nil, err
	}
	if connType == "udp" {
		return &Address{
			Type:       connType,
			IP:         parentUdpAddr.IP,
			Port:       parentUdpAddr.Port,
			Zone:       parentUdpAddr.Zone,
			UdpParent:  parentUdpAddr,
			TcpParent:  parentTcpAddr,
			addrString: addrFormatted,
		}, nil
	} else if connType == "tcp" {
		return &Address{
			Type:       connType,
			IP:         parentTcpAddr.IP,
			Port:       parentTcpAddr.Port,
			Zone:       parentTcpAddr.Zone,
			UdpParent:  parentUdpAddr,
			TcpParent:  parentTcpAddr,
			addrString: addrFormatted,
		}, nil
	}
	return nil, fmt.Errorf("unsupported connection type %s", connType)
}

func NewAddressFromUDP(udpAddr *net.UDPAddr) *Address {
	return &Address{
		Type:       "udp",
		IP:         udpAddr.IP,
		Port:       udpAddr.Port,
		Zone:       udpAddr.Zone,
		UdpParent:  udpAddr,
		TcpParent:  nil,
		addrString: udpAddr.String(),
	}
}
func NewAddressFromTCP(tcpAddr *net.TCPAddr) *Address {
	return &Address{
		Type:       "tcp",
		IP:         tcpAddr.IP,
		Port:       tcpAddr.Port,
		Zone:       tcpAddr.Zone,
		UdpParent:  nil,
		TcpParent:  tcpAddr,
		addrString: tcpAddr.String(),
	}
}

func (a *Address) String() string {
	return a.addrString
}
