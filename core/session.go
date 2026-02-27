package core

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

type Session interface {
	Open(serverAddr *net.UDPAddr, layerChains []NetLayer, defaultLayer uint8, layersIndexes []uint8, login string, password string) (ip net.IP, err error)
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
}

type UdpSession struct {
	Conn   net.Conn
	Reader io.Reader
	Writer io.Writer
	NLayer NetLayer
}

func (session *UdpSession) Open(serverAddr *net.UDPAddr, layerChains []NetLayer, defaultLayer uint8, layersIndexes []uint8, login string, password string) (ip net.IP, err error) {
	session.Conn, err = net.DialUDP("udp", nil, serverAddr)

	_ = session.Conn.SetDeadline(time.Now().Add(3 * time.Second))
	var virtualIP net.IP
	for attempt := 1; attempt <= 3; attempt++ {
		virtualIP, session.NLayer, err = ClientHandshake(
			session,
			layerChains,
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
	return virtualIP, err
}

func (session *UdpSession) Read(b []byte) (n int, err error) {
	return session.Conn.Read(b)
}
func (session *UdpSession) Write(b []byte) (n int, err error) {
	return session.Conn.Write(b)
}
func (session *UdpSession) Close() error {
	return session.Conn.Close()
}
