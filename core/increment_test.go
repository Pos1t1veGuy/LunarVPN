package core

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNetworkIPIncrement(t *testing.T) {
	testCases := []struct {
		cidr      string
		expected  []string
		expectErr bool
	}{
		{
			cidr: "192.168.1.0/30",
			expected: []string{
				"192.168.1.2",
			},
			expectErr: true,
		},
		{
			cidr: "10.0.0.0/29",
			expected: []string{
				"10.0.0.1",
				"10.0.0.2",
				"10.0.0.3",
				"10.0.0.4",
				"10.0.0.5",
			},
			expectErr: true,
		},
		{
			cidr: "172.16.0.0/31",
			expected: []string{
				"172.16.0.0",
			},
			expectErr: true,
		},
		{
			cidr: "10.0.0.0/16",
			expected: []string{
				"10.0.0.1",
				"10.0.0.2",
				"10.0.0.3",
				"10.0.0.4",
			},
			expectErr: false,
		},
		{
			cidr: "10.255.255.247/24",
			expected: []string{
				"10.255.255.247",
				"10.255.255.248",
				"10.255.255.249",
				"10.255.255.250",
				"10.255.255.251",
				"10.255.255.252",
				"10.255.255.253",
				"10.255.255.254",
				"10.255.255.255",
				"10.255.255.1",
				"10.255.255.2",
				"10.255.255.3",
				"10.255.255.4",
			},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		network, err := NewNetwork(tc.cidr)
		require.NoError(t, err, "failed to create network for %s", tc.cidr)

		for i, expected := range tc.expected {
			ip, err := network.Next()
			if tc.expectErr && i >= len(tc.expected)-1 {
				require.Error(t, err, "expected error at the end of range for %s, %s", tc.cidr, tc.expected[i])
				require.Nil(t, ip)
				continue
			}

			require.NoError(t, err, "unexpected error for %s, %s", tc.cidr, tc.expected[i])
			require.Equal(t, expected, ip.String())
		}

		ip, err := network.Next()
		if tc.expectErr {
			require.Error(t, err, "expected error when exceeding range for %s", tc.cidr)
			require.Nil(t, ip)
		} else {
			require.NoError(t, err)
			require.NotNil(t, ip)
		}
	}
}
