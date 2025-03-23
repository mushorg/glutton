package udp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestThrottling(t *testing.T) {
	testIP := net.IPv4(192, 168, 1, 1).String()
	throttle[testIP] = throttleState{count: maxRequestCount + 1, last: time.Now().Unix()}
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "throttle",
			ip:       testIP,
			expected: true,
		},
		{
			name:     "no throttle",
			ip:       net.IPv4(192, 168, 1, 2).String(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok := shouldThrottle(tt.ip)
			require.Equal(t, tt.expected, ok)
		})
	}
}
