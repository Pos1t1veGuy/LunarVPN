package layers

import (
	"bytes"
	"testing"

	"github.com/Pos1t1veGuy/LunarVPN/core"
)

func TestNetLayersRoundTrip(t *testing.T) {
	testCases := []struct {
		name   string
		layers []core.NetLayer
		data   []byte
	}{
		{
			name: "debug",
			layers: []core.NetLayer{
				core.NewDebugLayer(true, false),
			},
			data: []byte("secret payload"),
		},
		{
			name: "xor",
			layers: []core.NetLayer{
				NewXorLayer(0x42),
			},
			data: []byte("secret payload"),
		},
		{
			name: "xor + debug",
			layers: []core.NetLayer{
				NewXorLayer(0x42),
				core.NewDebugLayer(true, false),
			},
			data: []byte("secret payload"),
		},
		{
			name: "debug + xor + xor",
			layers: []core.NetLayer{
				core.NewDebugLayer(true, false),
				NewXorLayer(0xAA),
				NewXorLayer(0xBB),
			},
			data: bytes.Repeat([]byte{0xAB}, 1024),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pipeline := core.BuildNetLayers(tc.layers...)

			wrapped, err := pipeline.Wrap(tc.data)
			if err != nil {
				t.Fatalf("wrap failed: %v", err)
			}

			unwrapped, err := pipeline.Unwrap(wrapped)
			if err != nil {
				t.Fatalf("unwrap failed: %v", err)
			}

			if !bytes.Equal(unwrapped, tc.data) {
				t.Fatalf(
					"data mismatch:\nexpected: %x\ngot:      %x",
					tc.data,
					unwrapped,
				)
			}
		})
	}
}
