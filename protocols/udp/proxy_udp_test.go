package udp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/rules"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func setProxyUDPConfig(t *testing.T, capture bool, idleSeconds int) {
	t.Helper()
	prevCapture := viper.Get("capture_traffic.enabled")
	prevMax := viper.Get("max_tcp_payload")
	prevIdle := viper.Get("conn_timeout")
	prevDial := viper.Get("dial_timeout")
	viper.Set("capture_traffic.enabled", capture)
	viper.Set("max_tcp_payload", 4096)
	viper.Set("conn_timeout", idleSeconds)
	viper.Set("dial_timeout", 2)
	t.Cleanup(func() {
		viper.Set("capture_traffic.enabled", prevCapture)
		viper.Set("max_tcp_payload", prevMax)
		viper.Set("conn_timeout", prevIdle)
		viper.Set("dial_timeout", prevDial)
	})
}

func proxyUDPMetadata(target string) connection.Metadata {
	return connection.Metadata{
		Rule: &rules.Rule{
			Type: "proxy_udp",
			ProxyTarget: &rules.ProxyTarget{
				Host:        "127.0.0.1",
				Port:        0,
				DialAddress: target,
			},
		},
	}
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestHandleProxyUDP(t *testing.T) {
	setProxyUDPConfig(t, true, 1)
	upstream := startUDPEcho(t)
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 50000}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}
	payload := []byte("hello-quic")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := HandleProxyUDP(ctx, src, dst, payload, proxyUDPMetadata(upstream), testLogger{}, h)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.replies) >= 1
	}, 2*time.Second, 20*time.Millisecond)

	h.mu.Lock()
	require.Equal(t, append([]byte("echo:"), payload...), h.replies[0])
	h.mu.Unlock()

	cancel()
	require.Eventually(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.produced) == 1
	}, 2*time.Second, 20*time.Millisecond)

	h.mu.Lock()
	defer h.mu.Unlock()
	require.Equal(t, "proxy_udp", h.produced[0].handler)
	events, ok := h.produced[0].decoded.([]proxyEvent)
	require.True(t, ok)
	require.NotEmpty(t, events)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleProxyUDPMissingTarget(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 50000}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}

	err := HandleProxyUDP(context.Background(), src, dst, []byte("x"), connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Empty(t, h.produced)
	require.Empty(t, h.replies)
}

func TestHandleProxyUDPReusesFlow(t *testing.T) {
	setProxyUDPConfig(t, false, 2)
	upstream := startUDPEcho(t)
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.11"), Port: 50001}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	md := proxyUDPMetadata(upstream)

	require.NoError(t, HandleProxyUDP(ctx, src, dst, []byte("one"), md, testLogger{}, h))
	require.NoError(t, HandleProxyUDP(ctx, src, dst, []byte("two"), md, testLogger{}, h))

	require.Eventually(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.replies) >= 2
	}, 2*time.Second, 20*time.Millisecond)

	cancel()
	require.Eventually(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.produced) == 1
	}, 2*time.Second, 20*time.Millisecond)
}
