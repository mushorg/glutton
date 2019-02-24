package glutton

import (
	"context"
	"net"
	"testing"

	"github.com/spf13/viper"
)

func TestHTTPHandler(t *testing.T) {
	viper.Set("var-dir", "/tmp/")
	viper.Set("confpath", "config/")
	g, err := New()
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	go func() {
		data := []byte("GET / HTTP/1.1\r\n\r\n")
		if _, err := server.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	ctx := context.Background()
	if err := g.HandleHTTP(ctx, client); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}
