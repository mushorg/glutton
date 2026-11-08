package banners

import (
	"bytes"
	"encoding/binary"
)

// Check Point FireWall-1 SecuRemote topology service (FW1_topo, tcp/264;
// nmap-services calls the port bgmp). Clients open with a hello and the
// gateway accepts it with "Y\0\0\0"; a "securemote" request then returns the
// gateway's ICA certificate DN, "CN=<gateway>,O=<management>..<suffix>", which
// leaks the firewall and SmartCenter host names. The byte sequence follows
// Metasploit's auxiliary/gather/checkpoint_hostname, which sends the hello as
// "Q\0\0\0" "\0\0\0!", expects exactly "Y\0\0\0", then sends
// "\0\0\0\x0bsecuremote\0" and parses /CN=(.+),O=.(.+?)\./ from the reply. The
// length-prefixed, NUL-terminated framing of the DN reply mirrors the request
// and is unverified against a live gateway.

var (
	// fw1TopoHello is the client hello (Ochi tcp/264, 207.90.244.27).
	fw1TopoHello = []byte{'Q', 0, 0, 0, 0, 0, 0, '!'}
	// fw1TopoAccept is the gateway's reply to the hello.
	fw1TopoAccept = []byte{'Y', 0, 0, 0}
	// fw1TopoSecuRemote is the topology request that follows the accept.
	fw1TopoSecuRemote = append([]byte{0, 0, 0, 0x0b}, "securemote\x00"...)
	// fw1TopoDN is the persona's ICA DN: gateway cpgw-edge01 managed by
	// cpmgmt01, with a made-up ICA suffix.
	fw1TopoDN = "CN=cpgw-edge01,O=cpmgmt01..k7x3qa"
)

// fw1TopoDNReply frames dn as a big-endian length (including the NUL) and the
// NUL-terminated string.
func fw1TopoDNReply(dn string) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(dn)+1))
	b = append(b, dn...)
	return append(b, 0)
}

// fw1TopoReply answers the hello and the securemote request on any port. Both
// are matched exactly, so other payloads that start with 'Q' or a 4-byte
// length are left alone.
func fw1TopoReply(data []byte) (Response, bool) {
	switch {
	case bytes.Equal(data, fw1TopoHello):
		return Response{Name: "fw1-topology-hello", Data: fw1TopoAccept}, true
	case bytes.Equal(data, fw1TopoSecuRemote):
		return Response{Name: "fw1-topology-securemote", Data: fw1TopoDNReply(fw1TopoDN), Close: true}, true
	}
	return Response{}, false
}
