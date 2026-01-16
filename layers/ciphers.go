package layers

import (
	"crypto/sha256"
	"errors"

	"github.com/Pos1t1veGuy/LunarVPN/core"
)

type XorLayer struct {
	key []byte
	core.BaseLayer
}

func NewXorLayer(key []byte) *XorLayer {
	if len(key) == 0 {
		panic("xor key must not be empty")
	}
	return &XorLayer{
		key: key,
		BaseLayer: core.BaseLayer{
			Description: "XOR encryption layer",
		},
	}
}

func (xor *XorLayer) Wrap(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ xor.key[i%len(xor.key)]
	}
	return xor.WrapNext(out)
}

func (xor *XorLayer) Unwrap(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ xor.key[i%len(xor.key)]
	}
	return xor.UnwrapNext(out)
}

func (xor *XorLayer) GetDescription() string {
	return xor.Description
}
func (xor *XorLayer) Init(ctx *core.SessionContext) error {
	if ctx == nil || len(ctx.MasterSecret) == 0 {
		return errors.New("session context is not initialized")
	}

	h := sha256.New()
	h.Write(ctx.MasterSecret)
	h.Write([]byte("xor"))

	xor.key = h.Sum(nil)

	return nil
}
func (xor *XorLayer) Clone() core.NetLayer {
	return &XorLayer{
		key: xor.key,
	}
}
