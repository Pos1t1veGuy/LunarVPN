package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

type Controller interface {
	Start()
	Stop() error
}

type HttpController struct {
	Host   string
	Port   int
	server *http.Server
	client *Client
}

func (client *Client) NewHttpController(host string, port int) *HttpController {

	controller := &HttpController{
		Host:   host,
		Port:   port,
		client: client,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("POST /tunnel/start", client.startTunnel)
	mux.HandleFunc("POST /tunnel/stop", client.stopTunnel)
	mux.HandleFunc("GET /status", client.status)

	controller.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", host, port),
		Handler: mux,
	}

	client.Controller = controller
	return controller
}

func (controller *HttpController) Start() {
	go func() {
		err := controller.server.ListenAndServe()

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("controller failed")
		}
	}()
	log.Info().
		Str("state", "connecting").
		Str("Host", controller.Host).
		Int("Port", controller.Port).
		Msg("HttpController started")
}
func (controller *HttpController) Stop() error {
	return controller.server.Shutdown(context.Background())
}

type StatusResponse struct {
	Version         string `json:"version"`
	TunnelState     string `json:"tunState"`
	ConnectionState string `json:"connState"`
	Connections     uint   `json:"conns"`
	Ping            uint   `json:"ping"`

	Server   string   `json:"server"`
	Port     uint     `json:"port"`
	Protocol string   `json:"protocol"`
	Layers   []string `json:"layers"`
}

func (client *Client) status(writer http.ResponseWriter, request *http.Request) {
	resp := StatusResponse{
		Version:         client.Version,
		TunnelState:     client.Tunnel.GetState(),
		ConnectionState: client.Session.GetState(),
		Connections:     client.Session.GetConnsCount(),
		Ping:            uint(client.Session.GetPing().GetValue().Milliseconds()),

		Protocol: client.Session.Type(),
		Server:   "N/A",
		Port:     0,
		Layers:   []string{"N/A"},
	}
	if client.ServerAddr != nil {
		resp.Server = client.ServerAddr.IP.String()
		resp.Port = uint(client.ServerAddr.Port)
	}
	if client.Session.GetNLayer() != nil {
		resp.Layers = []string{}
		for layer := client.Session.GetNLayer(); layer != nil; layer = layer.GetNext() {
			resp.Layers = append(resp.Layers, layer.GetDescription())
		}
	}

	writer.Header().Set(
		"Content-Type",
		"application/json",
	)

	_ = json.NewEncoder(writer).Encode(resp)
}

func (client *Client) startTunnel(writer http.ResponseWriter, request *http.Request) {
	client.Tunnel.Stop() // clear broken routes
	err := client.Tunnel.Start(client.VirtualIP.String())

	if err != nil {
		http.Error(
			writer,
			err.Error(),
			http.StatusInternalServerError,
		)
		log.Error().
			Str("state", "connecting").
			Str("Net", client.CIDR).
			Err(err).
			Msg("Tunnel broken")
		return
	}
	writer.WriteHeader(http.StatusOK)
	log.Info().
		Str("state", "connecting").
		Str("Net", client.CIDR).
		Msg("Tunnel started")
}

func (client *Client) stopTunnel(writer http.ResponseWriter, request *http.Request) {
	client.Tunnel.Stop()
	writer.WriteHeader(http.StatusOK)
	log.Info().
		Str("state", "disconnecting").
		Str("Net", client.CIDR).
		Msg("Tunnel stopped")
}
