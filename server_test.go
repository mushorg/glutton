package main

import "testing"

func TestPort2Protocol(t *testing.T) {
	prot := getProtocol(80, "tcp")
	if prot.Name != "http" {
		t.Fatalf("Got %s instead of http", prot.Name)
	}
}
