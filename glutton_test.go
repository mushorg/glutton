package glutton

import (
	"testing"

	"github.com/spf13/viper"
)

func TestPort2Protocol(t *testing.T) {
}

func TestNew(t *testing.T) {
	viper.Set("var-dir", "/tmp/glutton")
	viper.Set("confpath", "./config")
	g, err := New()
	if err != nil {
		t.Fatal(err)
	}
	g.registerHandlers()
}
