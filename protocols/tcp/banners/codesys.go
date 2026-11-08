package banners

import (
	"bytes"
	"math/rand/v2"
)

// CODESYS V2 runtime (3S-Smart Software Solutions) answers a 7-byte discovery
// query on tcp/1200 and tcp/2455 with its runtime info. The query is
// bb bb 01 00 00 00 01 for little-endian runtimes and bb bb 01 00 00 01 01 for
// big-endian ones (nmap codesys-v2-discover, Shodan's codesys module). The
// reply starts with bb bb and carries NUL-terminated strings in 32-byte fields
// at offsets 64 (OS name), 96 (OS type) and 128 (product name), which is where
// nmap's script reads them. The rest of the header is not parsed by scanners;
// its contents here are a guess, as no live capture was available.

var (
	codesysQueryLE = mustHex("bbbb0100000001")
	codesysQueryBE = mustHex("bbbb0100000101")
)

const (
	codesysFieldLen   = 32
	codesysOSNameOff  = 64
	codesysOSTypeOff  = 96
	codesysProductOff = 128
	codesysReplyLen   = codesysProductOff + codesysFieldLen
)

// codesysIdentity is the runtime info in the discovery reply.
type codesysIdentity struct {
	osName, osType, product string
}

// codesysPersonas are runtime info strings real CODESYS V2 controllers
// report to Shodan (Nucleus-based PLCs, Windows CE panels, WAGO Linux PFCs).
var codesysPersonas = []codesysIdentity{
	{"Nucleus PLUS", "Nucleus PLUS version unknown", "3S-Smart Software Solutions"},
	{"Windows", "CE.net (5.0)", "3S-Smart Software Solutions"},
	{"Linux", "2.6.29", "3S-Smart Software Solutions"},
}

// codesysRuntime is drawn once per run, so a sensor keeps one identity.
var codesysRuntime = codesysPersonas[rand.IntN(len(codesysPersonas))]

func isCodesysQuery(data []byte) bool {
	return bytes.Equal(data, codesysQueryLE) || bytes.Equal(data, codesysQueryBE)
}

// codesysInfo builds the discovery reply for id.
func codesysInfo(id codesysIdentity) []byte {
	reply := make([]byte, codesysReplyLen)
	reply[0], reply[1] = 0xbb, 0xbb
	// strings longer than a field are cut so the NUL terminator stays
	copy(reply[codesysOSNameOff:codesysOSNameOff+codesysFieldLen-1], id.osName)
	copy(reply[codesysOSTypeOff:codesysOSTypeOff+codesysFieldLen-1], id.osType)
	copy(reply[codesysProductOff:codesysProductOff+codesysFieldLen-1], id.product)
	return reply
}

func codesysReply(data []byte) (Response, bool) {
	if !isCodesysQuery(data) {
		return Response{}, false
	}
	return Response{Name: "codesys-info", Data: codesysInfo(codesysRuntime)}, true
}
