//go:build android

package core

//
//import (
//	"os"
//	"time"
//
//	"github.com/rs/zerolog/log"
//)
//
//// +build android
//
//package core
//
//import (
//	"os"
//)
//
//type AndroidInterfaceAdapter struct {
//	name  string
//	fd    *os.File
//	index int
//}
//
//func NewAndroidInterfaceAdapter(fd int) *AndroidInterfaceAdapter {
//	return &AndroidInterfaceAdapter{
//		name:  "android-vpn",
//		fd:    os.NewFile(uintptr(fd), "vpn"),
//		index: 0,
//	}
//}
//
//func (adapter *AndroidInterfaceAdapter) Name() string {
//	return adapter.name
//}
//
//func (adapter *AndroidInterfaceAdapter) Index() int {
//	// Android не предоставляет индекс интерфейса
//	return adapter.index
//}
//
//func (adapter *AndroidInterfaceAdapter) Read(p []byte) (int, error) {
//	return adapter.fd.Read(p)
//}
//
//func (adapter *AndroidInterfaceAdapter) Write(b []byte) (int, error) {
//	return adapter.fd.Write(b)
//}
//
//func (adapter *AndroidInterfaceAdapter) Close() {
//	_ = adapter.fd.Close()
//}
//
//func NewClientAndroid(addr string, port int, whiteList []string, blackList []string, netLayers []NetLayer) *Client {
//	adapter, err := NewAndroidInterfaceAdapter()
//	if err != nil {
//		log.Fatal().
//			Err(err).
//			Str("state", "starting").
//			Msg("Failed to create adapter")
//	}
//	return &Client{
//		LayerChains: netLayers,
//		WhiteList:   whiteList,
//		BlackList:   blackList,
//		Stopping:    make(chan struct{}),
//		Ping:        NewPing(20 * time.Second),
//		Endpoint:    *NewEndpoint(addr, port, "0.0.0.0/0", adapter, NewTunnel),
//	}
//}
