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
	GetPing() *Ping

	Open(client *Client, defaultLayer uint8, layersIndexes []uint8, login string, password string) (ip net.IP, err error)
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
}

type UdpSession struct {
	Conn   net.Conn
	Reader io.Reader
	Writer io.Writer
	NLayer NetLayer

	Ping     *Ping
	Stopping chan struct{}
}

func NewUdpSession(pingDuration time.Duration) *UdpSession {
	return &UdpSession{
		Ping:     NewPing(pingDuration),
		Stopping: make(chan struct{}),
	}
}

func (session *UdpSession) GetConnection() net.Conn {
	return session.Conn
}
func (session *UdpSession) GetPing() *Ping {
	return session.Ping
}

func (session *UdpSession) Open(client *Client, defaultLayer uint8, layersIndexes []uint8, login, password string) (ip net.IP, err error) {
	session.Conn, err = net.DialUDP("udp", nil, client.ServerAddr)

	_ = session.Conn.SetDeadline(time.Now().Add(3 * time.Second))
	var virtualIP net.IP
	for attempt := 1; attempt <= 3; attempt++ {
		virtualIP, session.NLayer, err = ClientHandshake(
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
		return nil, errors.New("all handshake attempts failed. Server is unavailable")
	}
	_ = session.Conn.SetDeadline(time.Time{})

	pingPacket, err := MakePingPacket(virtualIP, client.ServerAddr.IP)
	if err != nil {
		return nil, err
	}
	go session.PingLoop(pingPacket, client.SendPacket, 5*time.Second)

	return virtualIP, err
}
func (session *UdpSession) Close() error {
	close(session.Stopping)
	return session.Conn.Close()
}

func (session *UdpSession) Read(buf []byte) (n int, err error) {
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
func (session *UdpSession) Write(b []byte) (n int, err error) {
	wrapped, err := session.NLayer.Wrap(b)
	if err != nil {
		return n, err
	}
	return session.Conn.Write(wrapped)
}

func (session *UdpSession) PingLoop(packet *Packet, sendPacket func(packet *Packet), duration time.Duration) {
	attempts := 0

	for {
		select {
		case <-session.Stopping:
			return
		default:
		}

		session.Ping.Start()
		sendPacket(packet)
		log.Debug().
			Str("state", "ping").
			Msg("Ping server")

		time.Sleep(duration)

		if !session.Ping.Response {
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
			}
		} else {
			attempts = 0
		}
	}
}

type UdpSessionPool struct {
	Sessions    []*UdpSession
	MaxSessions uint

	Ping       *PingGroup
	mu         sync.RWMutex
	readBuffer chan []byte
	Stopping   chan struct{}
}

func NewUdpSessionPool(maxSessions uint, pingDuration time.Duration) *UdpSessionPool {
	sessions := make([]*UdpSession, 0, maxSessions)

	for i := uint(0); i < maxSessions; i++ {
		sessions = append(sessions, NewUdpSession(pingDuration))
	}
	mgr := &UdpSessionPool{
		Sessions:    sessions,
		MaxSessions: maxSessions,
		readBuffer:  make(chan []byte, 1024),
		Stopping:    make(chan struct{}),
	}
	mgr.Ping = NewPingGroup(sessions)
	return mgr
}

func (mgr *UdpSessionPool) Open(client *Client, defaultLayer uint8, layersIndexes []uint8, login, password string) (ip net.IP, err error) {
	var virtualIP net.IP
	var opened []*UdpSession

	for _, session := range mgr.Sessions {
		virtualIP, err = session.Open(client, defaultLayer, layersIndexes, login, password)
		opened = append(opened, session)

		if err != nil {
			for _, s := range opened {
				_ = s.Close()
			}
			return nil, err
		}
		go mgr.ReaderLoop(session)
	}
	return virtualIP, nil
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

		if session.Ping.Response {
			alive = append(alive, session)
		} else {
			dead = append(dead, session)
		}
	}

	sort.Slice(alive, func(i, j int) bool {
		return alive[i].Ping.Value < alive[j].Ping.Value
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
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		select {
		case mgr.readBuffer <- packet:
		case <-mgr.Stopping:
			return
		}
	}
}

type PingGroup struct {
	Sessions []*UdpSession
	Value    time.Duration
	mu       sync.Mutex
}

func NewPingGroup(sessions []*UdpSession) *PingGroup {
	return &PingGroup{Sessions: sessions}
}

func (pg *PingGroup) Calculate() {
	pg.mu.Lock()
	defer pg.mu.Unlock()

	var sum time.Duration
	var count int

	for _, session := range pg.Sessions {
		if session.Ping == nil {
			continue
		}
		session.Ping.Calculate()
		if !session.Ping.Response {
			continue
		}

		sum += session.Ping.Value
		count++
	}
	if count == 0 {
		pg.Value = 0
	} else {
		pg.Value = sum / time.Duration(count)
	}
}
