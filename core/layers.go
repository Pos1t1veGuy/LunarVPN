package core

import (
	"github.com/rs/zerolog/log"
)

type NetLayer interface {
	Wrap(data []byte) ([]byte, error)
	Unwrap(data []byte) ([]byte, error)
	SetNext(next NetLayer)
	GetNext() NetLayer

	GetDescription() string
	Init(ctx *SessionContext) error
	Clone() NetLayer
}

type BaseLayer struct {
	next        NetLayer
	Description string
}

func (b *BaseLayer) SetNext(next NetLayer) {
	b.next = next
}

func (b *BaseLayer) GetNext() NetLayer {
	return b.next
}

func (b *BaseLayer) WrapNext(data []byte) ([]byte, error) {
	if b.next == nil {
		return data, nil
	}
	return b.next.Wrap(data)
}

func (b *BaseLayer) UnwrapNext(data []byte) ([]byte, error) {
	if b.next == nil {
		return data, nil
	}
	return b.next.Unwrap(data)
}

type DebugLayer struct {
	showLen     bool
	showContent bool

	BaseLayer
}

func NewDebugLayer(showLen bool, showContent bool) *DebugLayer {
	return &DebugLayer{
		showLen:     showLen,
		showContent: showContent,
		BaseLayer: BaseLayer{
			Description: "Debug layer (logging packets)",
		},
	}
}

func (debug *DebugLayer) log(direction string, data []byte) {
	info := log.Info().
		Str("state", "debugLayer").
		Str("direction", direction)

	if debug.showLen {
		info = info.Int("len", len(data))
	}

	if debug.showContent {
		const maxDump = 128

		if len(data) > maxDump {
			info = info.
				Bytes("data", data[:maxDump]).
				Int("truncated", len(data)-maxDump)
		} else {
			info = info.Bytes("data", data)
		}
	}

	info.Msg("traffic")
}

func (debug *DebugLayer) Wrap(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	copy(out, data)
	debug.log("wrap", out)
	return debug.WrapNext(out)
}
func (debug *DebugLayer) Unwrap(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	copy(out, data)
	debug.log("unwrap", out)
	return debug.UnwrapNext(out)
}

func (debug *DebugLayer) GetDescription() string {
	return debug.Description
}
func (debug *DebugLayer) Init(ctx *SessionContext) error {
	return nil
}
func (debug *DebugLayer) Clone() NetLayer {
	return &DebugLayer{
		showLen:     debug.showLen,
		showContent: debug.showContent,
		BaseLayer: BaseLayer{
			Description: "Debug layer (logging packets)",
		},
	}
}

func BuildNetLayers(layers ...NetLayer) NetLayer {
	for i := 0; i < len(layers)-1; i++ {
		layers[i].SetNext(layers[i+1])
	}
	return layers[0]
}
