package core

import (
	"errors"
	"fmt"
	"io"
	"net"
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
	session.Stopping <- struct{}{}
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
		fmt.Println(session.Stopping)
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

type MuxSession struct {
	Sessions    []*UdpSession
	MaxSessions uint

	mu sync.Mutex
	UdpSession
}

func NewMuxUdpSession(maxSessions uint, maxStreams uint) *MuxSession {
	return &MuxSession{
		Sessions:    make([]*UdpSession, 0, maxStreams),
		MaxSessions: maxSessions,
	}
}

func (mgr *MuxSession) Write(b []byte) (int, error) {
	session := mgr.GetStrongestSession()
	return session.Write(b)
}

func (mgr *MuxSession) Read(b []byte) (int, error) {
	for _, sess := range mgr.Sessions {
		if n, err := sess.Read(b); err == nil && n > 0 {
			return n, nil
		}
	}
	time.Sleep(10 * time.Millisecond)
	return 0, nil
}

func (mgr *MuxSession) GetStrongestSession() *UdpSession {
	mgr.mu.Lock()
	session := mgr.Sessions[0]
	mgr.mu.Unlock()
	return session
}
