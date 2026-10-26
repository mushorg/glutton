package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/socks"
	"github.com/spf13/viper"
)

// benchSOCKSTLS replays one flood session: SOCKS5 CONNECT host:443, a TLS
// handshake in the tunnel, then one HTTP GET answered with the judge reply.
func benchSOCKSTLS(b *testing.B, host func(i int) string) {
	b.Helper()
	b.Chdir(b.TempDir())
	prev := viper.Get("max_tcp_payload")
	viper.Set("max_tcp_payload", 4096)
	b.Cleanup(func() { viper.Set("max_tcp_payload", prev) })
	judge := socks.TunnelHTTPReply()
	reply := make([]byte, 10)
	got := make([]byte, len(judge))
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		name := host(i)
		connect := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(name))}, name...)
		connect = append(connect, 0x01, 0xbb)
		client, serverConn := net.Pipe()
		hp := newFakeHoneypot()
		done := make(chan error, 1)
		go func() {
			done <- HandleSOCKS(context.Background(), serverConn, connection.Metadata{TargetPort: 1}, &recordingLogger{}, hp)
		}()
		if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(client, reply[:2]); err != nil {
			b.Fatal(err)
		}
		if _, err := client.Write(connect); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(client, reply); err != nil {
			b.Fatal(err)
		}
		tc := tlsJudgeClient(client, name)
		if err := tc.Handshake(); err != nil {
			b.Fatal(err)
		}
		if _, err := fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", name); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(tc, got); err != nil {
			b.Fatal(err)
		}
		_ = client.Close()
		if err := <-done; err != nil {
			b.Fatal(err)
		}
		<-hp.produced
	}
}

func BenchmarkSOCKSTLSNewHost(b *testing.B) {
	run := fmt.Sprintf("%p", b) // fresh names per benchmark run, not cached
	benchSOCKSTLS(b, func(i int) string { return fmt.Sprintf("h%d-%s.example.com", i, run[2:]) })
}

func BenchmarkSOCKSTLSSameHost(b *testing.B) {
	benchSOCKSTLS(b, func(int) string { return "gunceladreslergiris3.com" })
}
