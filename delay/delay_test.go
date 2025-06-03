package delay

import (
	"testing"
	"time"
)

func TestDelayHandler(t *testing.T) {
	config := DelayConfig{
		Global: DelayRange{Min: 50, Max: 200},
		PerPort: []PortDelay{
			{
				Port:      5000,
				Min:       100,
				Max:       300,
				Protocols: []string{"tcp"},
			},
		},
	}

	handler := NewDelayHandler(config)

	tests := []struct {
		name     string
		port     int
		protocol string
		minDelay time.Duration
		maxDelay time.Duration
	}{
		{
			name:     "TCP port 5000",
			port:     5000,
			protocol: "tcp",
			minDelay: 100 * time.Millisecond,
			maxDelay: 300 * time.Millisecond,
		},
		{
			name:     "Global fallback",
			port:     5001,
			protocol: "udp",
			minDelay: 50 * time.Millisecond,
			maxDelay: 200 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delay := handler.GetDelay(tt.port, tt.protocol)
			if delay < tt.minDelay || delay > tt.maxDelay {
				t.Errorf("Delay %v outside expected range [%v, %v]",
					delay, tt.minDelay, tt.maxDelay)
			}
		})
	}
}
