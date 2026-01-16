package core

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
)

type ClientHello struct {
	ProtocolVersion byte // (1 - default version)
	ClientRandom    [32]byte
	ChainLength     uint8
	Chain           []uint8 // every byte is a NetLayer index to make a chain of some NetLayers
	AuthDataLength  uint8
	AuthData        []byte
	Rsv             [4]byte
}

type ServerHello struct {
	ProtocolVersion byte // (1 - default version)
	ServerRandom    [32]byte
	ServerResponse  byte   // 8 bits. 1. packet validation bit; 2. auth bit; 3. chain bit. 8. server error bit
	AssignedIP      net.IP // always IPv4. Return 0.0.0.0 if server refused client's connection
	Rsv             [4]byte
}

const (
	ServerRespPacketValid = 1 << 7
	ServerRespAuthOK      = 1 << 6
	ServerRespChainOK     = 1 << 5
	ServerRespServerError = 1 << 0
)

func NewClientHello(chain []byte, authData []byte) *ClientHello {
	ch := &ClientHello{
		ProtocolVersion: ProtocolVersion,
		ChainLength:     uint8(len(chain)),
		Chain:           chain,
		AuthDataLength:  uint8(len(authData)),
		AuthData:        authData,
	}

	_, _ = rand.Read(ch.ClientRandom[:])
	return ch
}

func NewServerHello(assignedIP net.IP, valid, auth, chain, serverErr bool) *ServerHello {
	var resp byte
	if valid {
		resp |= ServerRespPacketValid
	}
	if auth {
		resp |= ServerRespAuthOK
	}
	if chain {
		resp |= ServerRespChainOK
	}
	if serverErr {
		resp |= ServerRespServerError
	}

	sh := &ServerHello{
		ProtocolVersion: ProtocolVersion,
		ServerResponse:  resp,
		AssignedIP:      assignedIP,
	}

	_, _ = rand.Read(sh.ServerRandom[:])
	return sh
}

func MarshalClientHello(ch *ClientHello) ([]byte, error) {
	buf := []byte{ch.ProtocolVersion}
	buf = append(buf, ch.ClientRandom[:]...)

	buf = append(buf, ch.ChainLength)
	if int(ch.ChainLength) != len(ch.Chain) {
		return nil, errors.New("invalid chain length")
	}
	buf = append(buf, ch.Chain...)

	buf = append(buf, ch.AuthDataLength)
	if int(ch.AuthDataLength) != len(ch.AuthData) {
		return nil, errors.New("invalid auth data length")
	}
	buf = append(buf, ch.AuthData...)

	buf = append(buf, ch.Rsv[:]...)
	return buf, nil
}

func MarshalServerHello(sh *ServerHello) ([]byte, error) {
	buf := []byte{sh.ProtocolVersion}
	buf = append(buf, sh.ServerRandom[:]...)
	buf = append(buf, sh.ServerResponse)

	ip4 := sh.AssignedIP.To4()
	if ip4 == nil {
		return nil, errors.New("invalid IPv4")
	}
	buf = append(buf, ip4...)

	buf = append(buf, sh.Rsv[:]...)
	return buf, nil
}

func UnmarshalClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 1+32+1+1+4 {
		return nil, fmt.Errorf("data too short for ClientHello, minimum is %d", 1+32+1+1+4)
	}

	ch := &ClientHello{}
	offset := 0

	ch.ProtocolVersion = data[offset]
	if ch.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("invalid ProtocolVersion: %d", ch.ProtocolVersion)
	}
	offset++

	copy(ch.ClientRandom[:], data[offset:offset+32])
	offset += 32

	ch.ChainLength = data[offset]
	offset++

	if int(ch.ChainLength) > len(data)-offset-1-4 || int(ch.ChainLength) <= 0 {
		return nil, fmt.Errorf("invalid chain length: %d", int(ch.ChainLength))
	}
	ch.Chain = append([]byte(nil), data[offset:offset+int(ch.ChainLength)]...)
	offset += int(ch.ChainLength)

	ch.AuthDataLength = data[offset]
	offset++

	if int(ch.AuthDataLength) > len(data)-offset-4 {
		return nil, fmt.Errorf("invalid auth data length: %d", int(ch.ChainLength))
	}
	ch.AuthData = append([]byte(nil), data[offset:offset+int(ch.AuthDataLength)]...)
	offset += int(ch.AuthDataLength)

	copy(ch.Rsv[:], data[offset:offset+4])

	return ch, nil
}

func UnmarshalServerHello(data []byte) (*ServerHello, error) {
	if len(data) < 1+32+1+4+4 {
		return nil, fmt.Errorf("data too short for ServerHello, minimum is %d", 1+32+1+1+4)
	}

	sh := &ServerHello{}
	offset := 0

	sh.ProtocolVersion = data[offset]
	if sh.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("invalid ProtocolVersion: %d", sh.ProtocolVersion)
	}
	offset++

	copy(sh.ServerRandom[:], data[offset:offset+32])
	offset += 32

	sh.ServerResponse = data[offset]
	offset++

	sh.AssignedIP = net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
	offset += 4

	copy(sh.Rsv[:], data[offset:offset+4])

	return sh, nil
}

func (client *Client) Handshake(layersIndexes []uint8, authData []byte, defaultLayer uint8) (net.IP, NetLayer, error) {
	clientHello := NewClientHello(layersIndexes, authData)
	helloBytes, err := MarshalClientHello(clientHello)
	handshakeLayer := client.LayerChains[defaultLayer]

	if err != nil {
		return nil, nil, err
	}

	helloWrapped, err := handshakeLayer.Wrap(helloBytes)
	if err != nil {
		return nil, nil, err
	}
	_, err = client.serverConn.Write(helloWrapped)

	if err != nil {
		return nil, nil, err
	}

	buf := make([]byte, 1024)

	for {
		n, err := client.serverConn.Read(buf)
		if err != nil {
			return nil, nil, err
		}
		helloUnwrapped, err := handshakeLayer.Wrap(buf[:n])
		if err != nil {
			return nil, nil, err
		}
		serverHello, err := UnmarshalServerHello(helloUnwrapped)
		if err != nil {
			return nil, nil, err
		}

		if serverHello.ServerResponse&ServerRespPacketValid == 0 {
			return nil, nil, errors.New("client packet is invalid")
		}
		if serverHello.ServerResponse&ServerRespAuthOK == 0 {
			return nil, nil, errors.New("server auth failed")
		}
		if serverHello.ServerResponse&ServerRespChainOK == 0 {
			return nil, nil, errors.New("server refused NetLayer chain")
		}
		if serverHello.ServerResponse&ServerRespServerError != 0 {
			return nil, nil, errors.New("server error")
		}

		if serverHello.AssignedIP.Equal(net.IPv4zero) {
			return nil, nil, errors.New("server assigned zero IP")
		}
		ip4 := serverHello.AssignedIP.To4()
		if ip4 == nil {
			return nil, nil, fmt.Errorf("server assigned invalid IP")
		}

		ctx, err := DeriveSessionContext(clientHello, serverHello)
		if err != nil {
			return nil, nil, err
		}

		layersToBuild := make([]NetLayer, 0, len(clientHello.Chain))
		for i := 0; i < len(clientHello.Chain); i++ {
			idx := int(clientHello.Chain[i])
			if idx >= len(client.LayerChains) {
				return nil, nil, fmt.Errorf("invalid layer index: %d", idx)
			}
			layersToBuild = append(layersToBuild, client.LayerChains[idx].Clone())
		}
		chain := BuildNetLayers(layersToBuild...)

		for layer := chain; layer != nil; layer = layer.GetNext() {
			if err = layer.Init(ctx); err != nil {
				return nil, nil, err
			}
		}

		return ip4, chain, nil
	}
}

func (server *Server) Handshake(n int, buf []byte, addr *net.UDPAddr, defaultLayer uint8, auth Authenticator) (*Peer, error) {
	sendResponse := func(response *ServerHello) error {
		serverHello, sendErr := MarshalServerHello(response)
		if sendErr != nil {
			return sendErr
		}
		helloWrapped, sendErr := server.LayerChains[defaultLayer].Wrap(serverHello)
		if sendErr != nil {
			return sendErr
		}
		if _, sendErr = server.Conn.WriteToUDP(helloWrapped, addr); sendErr != nil {
			return sendErr
		}
		return nil
	}

	helloUnwrapped, err := server.LayerChains[defaultLayer].Unwrap(buf[:n])
	if err != nil {
		return nil, err
	}
	clientHello, err := UnmarshalClientHello(helloUnwrapped)
	if err != nil {
		_ = sendResponse(NewServerHello(net.IPv4zero, false, false, false, false))
		return nil, err
	}

	if !auth.Authenticate(clientHello) {
		_ = sendResponse(NewServerHello(net.IPv4zero, true, false, false, false))
		return nil, fmt.Errorf("invalid login or password: %v", clientHello)
	}

	layersToBuild := make([]NetLayer, 0, len(clientHello.Chain))
	for i := 0; i < len(clientHello.Chain); i++ {
		idx := int(clientHello.Chain[i])
		if idx >= len(server.LayerChains) {
			_ = sendResponse(NewServerHello(net.IPv4zero, true, true, false, false))
			return nil, fmt.Errorf("invalid layer index: %d", idx)
		}
		layersToBuild = append(layersToBuild, server.LayerChains[idx].Clone())
	}
	chain := BuildNetLayers(layersToBuild...)

	virtualIP, err := server.Network.Next()
	if err != nil {
		_ = sendResponse(NewServerHello(net.IPv4zero, true, true, true, true))
		return nil, fmt.Errorf("get next virtual ip failed: %v", err)
	}
	successResponse := NewServerHello(virtualIP, true, true, true, false)

	ctx, err := DeriveSessionContext(clientHello, successResponse)
	if err != nil {
		_ = sendResponse(NewServerHello(net.IPv4zero, true, true, true, true))
		return nil, err
	}

	for layer := chain; layer != nil; layer = layer.GetNext() {
		if err = layer.Init(ctx); err != nil {
			_ = sendResponse(NewServerHello(net.IPv4zero, true, true, true, true))
			return nil, err
		}
	}

	err = sendResponse(successResponse)
	if err != nil {
		_ = sendResponse(NewServerHello(net.IPv4zero, true, true, true, true))
		return nil, fmt.Errorf("send ServerHello failed: %v", err)
	}
	peer := NewPeer(virtualIP, addr, chain, ctx, true)

	server.mu.Lock()
	server.Peers[addr.String()] = peer
	server.mu.Unlock()

	return peer, nil
}

func DeriveSessionContext(ch *ClientHello, sh *ServerHello) (*SessionContext, error) {
	if ch == nil || sh == nil {
		return nil, errors.New("nil hello")
	}

	h := sha256.New()
	h.Write(ch.ClientRandom[:])
	h.Write(sh.ServerRandom[:])

	return &SessionContext{
		ClientRandom: ch.ClientRandom,
		ServerRandom: sh.ServerRandom,
		MasterSecret: h.Sum(nil),
	}, nil
}
