package mqtt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// nmap's CONNECT from the tcp/12496 capture: MQTT 3.1.1, client id "nmap".
var nmapConnect = []byte{0x10, 0x10, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x1e, 0x00, 0x04, 'n', 'm', 'a', 'p'}

func TestLooksLikeConnect(t *testing.T) {
	v31 := []byte{0x10, 0x12, 0x00, 0x06, 'M', 'Q', 'I', 's', 'd', 'p', 0x03, 0x02, 0x00, 0x3c, 0x00, 0x04, 'n', 'm', 'a', 'p'}
	v5 := append([]byte{0x10, 0x10, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x05}, nmapConnect[9:]...)
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"nmap 3.1.1", nmapConnect, true},
		{"3.1 MQIsdp", v31, true},
		{"5.0", v5, true},
		{"header only up to level", nmapConnect[:9], true},
		{"empty", nil, false},
		{"truncated before level", nmapConnect[:8], false},
		{"wrong packet type", append([]byte{0x20}, nmapConnect[1:]...), false},
		{"reserved flags set", append([]byte{0x11}, nmapConnect[1:]...), false},
		{"wrong name", []byte{0x10, 0x10, 0x00, 0x04, 'M', 'Q', 'T', 'X', 0x04, 0x02, 0x00, 0x1e, 0x00, 0x00}, false},
		{"bad level", []byte{0x10, 0x10, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x09, 0x02, 0x00, 0x1e, 0x00, 0x00}, false},
		{"MQIsdp level 4", []byte{0x10, 0x12, 0x00, 0x06, 'M', 'Q', 'I', 's', 'd', 'p', 0x04, 0x02, 0x00, 0x3c}, false},
		{"remaining too short", []byte{0x10, 0x04, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04}, false},
		{"overlong length", []byte{0x10, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x04}, false},
		{"http", []byte("GET / HTTP/1.1\r\n"), false},
		{"tls hello", []byte{0x16, 0x03, 0x01, 0x00, 0xca, 0x01}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, LooksLikeConnect(tc.in))
		})
	}
}
