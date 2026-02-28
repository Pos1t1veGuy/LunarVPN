package core

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type Session interface {
	GetConnection() net.Conn
	GetPing() Ping
	SetIndex(index uint)

	Open(client *Client, defaultLayer uint8, layersIndexes []uint8, login string, password string) (ip *net.IP, err error)
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
}

type UdpSession struct {
	Index     uint
	Conn      net.Conn
	NLayer    NetLayer
	VirtualIP net.IP

	Ping         Ping
	Opened       bool
	pingDuration time.Duration
	Stopping     chan struct{}
}

func NewUdpSession(pingDuration time.Duration) *UdpSession {
	return &UdpSession{
		Ping:         NewDefaultPing(pingDuration),
		pingDuration: pingDuration,
		Stopping:     make(chan struct{}),
	}
}

func (session *UdpSession) GetConnection() net.Conn {
	return session.Conn
}
func (session *UdpSession) GetPing() Ping {
	return session.Ping
}

func (session *UdpSession) SetIndex(index uint) {
	session.Index = index
}

func (session *UdpSession) Reopen(client *Client, defaultLayer uint8, layersIndexes []uint8, login, password string) (ip *net.IP, err error) {
	_ = session.Close()
	return session.Open(client, defaultLayer, layersIndexes, login, password)
}

func (session *UdpSession) Open(client *Client, defaultLayer uint8, layersIndexes []uint8, login, password string) (ip *net.IP, err error) {
	for i := 0; i < 2; i++ {
		ip, err = session.SingleOpen(client, defaultLayer, layersIndexes, login, password)
		if err == nil {
			return ip, nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil, err
}

func (session *UdpSession) SingleOpen(client *Client, defaultLayer uint8, layersIndexes []uint8, login, password string) (ip *net.IP, err error) {
	session.Stopping = make(chan struct{})
	session.Conn, err = net.DialUDP("udp", nil, client.ServerAddr)
	if err != nil {
		return nil, err
	}

	_ = session.Conn.SetDeadline(time.Now().Add(5 * time.Second))
	for attempt := 1; attempt <= 3; attempt++ {
		session.VirtualIP, session.NLayer, err = ClientHandshake(
			session,
			client.LayerChains,
			defaultLayer,
			layersIndexes,
			[]byte(fmt.Sprintf("%s:%s", login, password)),
		)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return nil, err
	}
	_ = session.Conn.SetDeadline(time.Time{})

	pingPacket, err := MakePingPacket(session.VirtualIP, client.ServerAddr.IP)
	if err != nil {
		return nil, err
	}
	session.Ping = NewDefaultPing(session.pingDuration)
	go session.PingLoop(pingPacket, 5*time.Second)
	session.Opened = true

	return &session.VirtualIP, err
}
func (session *UdpSession) Close() error {
	close(session.Stopping)
	if session.Conn != nil {
		return session.Conn.Close()
	}
	session.Opened = false
	return nil
}

func (session *UdpSession) Read(buf []byte) (n int, err error) {
	if session.Opened {
		subbuf := make([]byte, len(buf))
		n, err = session.Conn.Read(subbuf)
		if err != nil {
			return n, err
		}
		unwrapped, err := session.NLayer.Unwrap(subbuf[:n])
		if err != nil {
			return n, err
		}
		copied := copy(buf, unwrapped)
		return copied, nil
	}
	return 0, errors.New("session closed")
}
func (session *UdpSession) Write(b []byte) (n int, err error) {
	if session.Opened {
		wrapped, err := session.NLayer.Wrap(b)
		if err != nil {
			return n, err
		}
		return session.Conn.Write(wrapped)
	}
	return 0, errors.New("session closed")
}

func (session *UdpSession) PingLoop(packet *Packet, duration time.Duration) {
	attempts := 0

	for {
		select {
		case <-session.Stopping:
			return
		default:
		}

		time.Sleep(duration)

		if !session.Opened {
			continue
		}

		session.Ping.Start()
		session.SendPacket(packet)
		log.Debug().
			Str("state", "ping").
			Msg("Ping server")

		if !session.Ping.GetResponse() {
			attempts++
			log.Debug().
				Str("state", "ping").
				Int("try", attempts).
				Msg("Server did not respond to ping request")
		} else {
			attempts = 0
			log.Debug().
				Str("state", "ping").
				Str("ping", session.Ping.GetValue().Truncate(time.Millisecond).String()).
				Msg("(UDP=>Interface) Pong received")
		}
	}
}

func (session *UdpSession) SendPacket(packet *Packet) {
	if session.Opened {
		bytes, err := MarshalPacket(packet)
		if err != nil {
			log.Debug().
				Err(err).
				Str("state", "SessionPacket").
				Int("len", len(bytes)).
				Int("AddrType", int(packet.AddrType)).
				Msg("(UDP<=Interface) Failed to marshal packet")
		}

		if _, err = session.Write(bytes); err != nil {
			log.Debug().
				Err(err).
				Str("state", "SessionPacket").
				Int("len", len(bytes)).
				Int("AddrType", int(packet.AddrType)).
				Msg("(UDP<=Interface) Failed to send packet")
		} else {
			log.Debug().
				Str("state", "SessionPacket").
				Int("len", len(bytes)).
				Int("AddrType", int(packet.AddrType)).
				Msg("(UDP<=Interface) Sent a packet")
		}
	}
}

type UdpSessionPool struct {
	Index        uint
	Conn         net.Conn
	PingDuration time.Duration
	Sessions     []*UdpSession
	MaxSessions  uint
	VirtualIP    net.IP

	ReopenMgr     func() (ip *net.IP, err error)
	OpenSession   func(session Session, index uint) (ip *net.IP, err error)
	ReopenSession func(session Session) (ip *net.IP, err error)

	Ping       Ping
	Opened     bool
	mu         sync.RWMutex
	readBuffer chan []byte
	Stopping   chan struct{}
}

func NewUdpSessionPool(maxSessions uint, localPingDuration time.Duration, globalPingDuration time.Duration) *UdpSessionPool {
	sessions := make([]*UdpSession, 0, maxSessions)

	for i := uint(0); i < maxSessions; i++ {
		sessions = append(sessions, NewUdpSession(localPingDuration))
	}
	mgr := &UdpSessionPool{
		PingDuration: globalPingDuration,
		Sessions:     sessions,
		MaxSessions:  maxSessions,
		readBuffer:   make(chan []byte, 1024),
		Stopping:     make(chan struct{}),
	}
	mgr.Ping = NewPingGroup(sessions)
	return mgr
}

func (mgr *UdpSessionPool) GetConnection() net.Conn {
	return mgr.Conn
}
func (mgr *UdpSessionPool) GetPing() Ping {
	return mgr.Ping
}

func (mgr *UdpSessionPool) SetIndex(index uint) {
	mgr.Index = index
}

func (mgr *UdpSessionPool) Reopen() (ip *net.IP, err error) {
	_ = mgr.Close()
	if mgr.Opened {
		return mgr.ReopenMgr()
	}
	return nil, errors.New("UdpSessionPool has not been opened and can be REopened")
}

func (mgr *UdpSessionPool) Open(client *Client, defaultLayer uint8, layersIndexes []uint8, login, password string) (ip *net.IP, err error) {
	for i := 0; i < 2; i++ {
		ip, err = mgr.SingleOpen(client, defaultLayer, layersIndexes, login, password)
		if err == nil {
			return ip, nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil, err
}

func (mgr *UdpSessionPool) SingleOpen(client *Client, defaultLayer uint8, layersIndexes []uint8, login, password string) (ip *net.IP, err error) {
	var opened []*UdpSession

	mgr.OpenSession = func(session Session, index uint) (ip *net.IP, err error) {
		session.SetIndex(index)
		return session.Open(client, defaultLayer, layersIndexes, login, password)
	}
	mgr.ReopenSession = func(session Session) (ip *net.IP, err error) {
		_ = session.Close()
		return session.Open(client, defaultLayer, layersIndexes, login, password)
	}
	mgr.ReopenMgr = func() (ip *net.IP, err error) {
		ip, err = mgr.Open(client, defaultLayer, layersIndexes, login, password)
		if err != nil {
			return nil, err
		}
		mgr.VirtualIP = *ip
		return ip, nil
	}

	for index, session := range mgr.Sessions {
		ip, err = mgr.OpenSession(session, uint(index))
		if err != nil || ip == nil {
			for _, s := range opened {
				_ = s.Close()
				return nil, err
			}
		}

		opened = append(opened, session)
	}

	for _, session := range mgr.Sessions {
		go mgr.ReaderLoop(session)
	}
	go mgr.PingLoop(mgr.PingDuration)

	mgr.Opened = true

	if ip != nil {
		mgr.VirtualIP = *ip
	}
	return ip, nil
}
func (mgr *UdpSessionPool) Close() error {
	close(mgr.Stopping)
	close(mgr.readBuffer)

	var err error
	for _, session := range mgr.Sessions {
		e := session.Close()
		if e != nil {
			err = e
		}
	}
	mgr.Opened = false
	return err
}

func (mgr *UdpSessionPool) Write(b []byte) (n int, err error) {
	for _, session := range mgr.FilterSessions() {
		if session == nil {
			return 0, errors.New("no session found")
		}
		n, err = session.Write(b)
		if err == nil {
			break
		}
	}
	return n, err
}

func (mgr *UdpSessionPool) Read(b []byte) (int, error) {
	packet, ok := <-mgr.readBuffer
	if !ok {
		return 0, io.EOF
	}
	n := copy(b, packet)
	return n, nil
}

func (mgr *UdpSessionPool) FilterSessions() []*UdpSession {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	if len(mgr.Sessions) == 0 {
		return nil
	}

	alive := make([]*UdpSession, 0, len(mgr.Sessions))
	dead := make([]*UdpSession, 0)

	for _, session := range mgr.Sessions {
		if session == nil || session.Ping == nil {
			continue
		}

		if session.Ping.GetResponse() {
			alive = append(alive, session)
		} else {
			dead = append(dead, session)
		}
	}

	sort.Slice(alive, func(i, j int) bool {
		return alive[i].Ping.GetValue() < alive[j].Ping.GetValue()
	})

	return append(alive, dead...)
}

func (mgr *UdpSessionPool) ReaderLoop(session *UdpSession) {
	buf := make([]byte, 65535)

	for {
		select {
		case <-mgr.Stopping:
			return
		default:
		}

		n, err := session.Read(buf)
		if err != nil {
			time.Sleep(1 * time.Millisecond)
			continue
		}

		bytes := make([]byte, n)
		copy(bytes, buf[:n])

		packet, err := UnmarshalPacket(buf[:n])
		if err != nil {
			time.Sleep(1 * time.Millisecond)
			continue
		}
		if !mgr.PacketAPI(session, packet) {
			select {
			case mgr.readBuffer <- bytes:
			case <-mgr.Stopping:
				return
			}
		}

		time.Sleep(1 * time.Millisecond)
	}
}

func (mgr *UdpSessionPool) PacketAPI(session *UdpSession, packet *Packet) bool {
	if packet.Type == 1 {
		switch packet.Rsv {
		case [4]byte{0, 0, 0, 0}: // disconnect
			log.Info().
				Str("state", "SessionAPI").
				Uint("ID", session.Index).
				Msg("(UDP=>Interface) Server disconnected one session")
		case [4]byte{0, 0, 0, 1}: // pong
			value := session.GetPing().Calculate()
			log.Debug().
				Str("state", "SessionAPI").
				Uint("ID", session.Index).
				Str("ping", value.Truncate(time.Millisecond).String()).
				Msg("(UDP=>Interface) Pong received to one session")
		}
		return true
	}
	return false
}

func (mgr *UdpSessionPool) PingLoop(duration time.Duration) {
	attempts := 0
	for {
		time.Sleep(duration)
		select {
		case <-mgr.Stopping:
			return
		default:
		}
		value := mgr.Ping.Calculate()
		if value > 0 {
			attempts = 0
			log.Info().
				Str("state", "ping").
				Str("ping", value.Truncate(time.Millisecond).String()).
				Msg("(UDP=>Interface) Average ping time")
		} else {
			attempts++
			log.Error().
				Str("state", "ping").
				Int("try", attempts).
				Msg("(UDP=>Interface) Server did not respond to ping request")

			if attempts > 5 && attempts%3 == 0 {
				tempSession := NewUdpSession(5 * time.Second)
				_, err := mgr.OpenSession(tempSession, mgr.MaxSessions+1)
				if err == nil {
					_ = tempSession.Close()
					_, err = mgr.ReopenMgr()
					if err == nil {
						time.Sleep(5 * time.Second)
					}
				}
			}
		}
	}
}

type PingGroup struct {
	Sessions []*UdpSession
	Value    time.Duration
	Response bool
	mu       sync.Mutex
}

func NewPingGroup(sessions []*UdpSession) *PingGroup {
	return &PingGroup{Sessions: sessions}
}

func (pg *PingGroup) GetValue() time.Duration {
	return pg.Value
}
func (pg *PingGroup) GetResponse() bool {
	return pg.Response
}

func (pg *PingGroup) Start() {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	for _, session := range pg.Sessions {
		session.Ping.Start()
	}
	pg.Response = false
}

func (pg *PingGroup) Calculate() time.Duration {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	pg.Response = true

	var sum time.Duration
	var count int

	for _, session := range pg.Sessions {
		if session.Ping == nil {
			continue
		}
		sum += session.Ping.GetValue()
		count++
	}
	if count == 0 {
		pg.Response = false
		pg.Value = 0
	} else {
		pg.Value = sum / time.Duration(count)
	}

	return pg.Value
}
