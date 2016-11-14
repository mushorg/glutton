package glutton

import "testing"

func TestPort2Protocol(t *testing.T) {
	prot := GetProtocol(80, "tcp")
	if prot.Name != "http" {
		t.Fatalf("Got %s instead of http", prot.Name)
	}
}

func TestPortParsing(t *testing.T) {
	LoadPorts("config/ports.yml")
}
