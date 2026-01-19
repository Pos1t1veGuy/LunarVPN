//go:build windows

package core

import (
	"net"
	"time"

	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wintun"
)

type WintunAdapter struct {
	DefaultAdapter

	Session wintun.Session
	Adapter *wintun.Adapter
}

func NewWintunAdapter(name string, sessionBufSize uint32) (*WintunAdapter, error) {
	adapter, err := wintun.OpenAdapter(name)
	if err != nil {
		adapter, err = wintun.CreateAdapter(name, "Wintun", nil)
		if err != nil {
			return nil, err
		}
	}
	session, err := adapter.StartSession(sessionBufSize)
	if err != nil {
		return nil, err
	}

	time.Sleep(300 * time.Millisecond)
	Interface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return &WintunAdapter{
		DefaultAdapter: DefaultAdapter{
			IfaceName:  name,
			IfaceIndex: Interface.Index,
		},
		Session: session,
		Adapter: adapter,
	}, nil
}

func (adapter *WintunAdapter) Read(p []byte) (int, error) {
	packet, err := adapter.Session.ReceivePacket()
	if err != nil {
		return 0, err
	}
	defer adapter.Session.ReleaseReceivePacket(packet)

	n := copy(p, packet)
	return n, nil
}

func (adapter *WintunAdapter) Write(b []byte) (int, error) {
	packet, err := adapter.Session.AllocateSendPacket(len(b))
	if err != nil {
		return 0, err
	}

	copy(packet, b)
	adapter.Session.SendPacket(packet)
	return len(b), nil
}

func (adapter *WintunAdapter) Close() {
	adapter.Session.End()
	adapter.Close()
}

func NewWindowsClient(addr string, port int, whiteList []string, blackList []string, netLayers []NetLayer) *Client {
	adapter, err := NewWintunAdapter("gotun0", 8*1024*1024)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "starting").
			Msg("Failed to create adapter")
	}
	return &Client{
		WhiteList:   whiteList,
		BlackList:   blackList,
		LayerChains: netLayers,
		Stopping:    make(chan struct{}),
		Ping:        NewPing(20 * time.Second),
		Endpoint:    *NewEndpoint(addr, port, "0.0.0.0/0", adapter, NewTunnel),
	}
}
