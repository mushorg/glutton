package banners

import (
	"bytes"
	"math/rand/v2"
	"strconv"
	"sync/atomic"
)

// NATS (tcp/4222) is server-first: nats-server sends an INFO line on connect
// before the client's CONNECT. The persona is a standalone nats-server 2.10.22
// without auth or TLS. Field names and order follow server.Info in
// nats-server; the git commit and Go version are unverified.

// natsServerID is the server's nkey public key, regenerated on every start: an
// 'N' prefix, then base32 (A-Z2-7) whose second character is A-D because of
// the prefix byte. It is per sensor run, so sensors do not share one ID.
var natsServerID = func() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b := make([]byte, 56)
	b[0] = 'N'
	b[1] = "ABCD"[rand.IntN(4)]
	for i := 2; i < len(b); i++ {
		b[i] = alphabet[rand.IntN(len(alphabet))]
	}
	return string(b)
}()

// natsClientID counts client connections like nats-server's per-client CID.
var natsClientID atomic.Uint64

func init() {
	natsClientID.Store(uint64(20 + rand.IntN(400)))
}

// natsInfo is the INFO greeting for the next client connection.
func natsInfo() []byte {
	return []byte(`INFO {"server_id":"` + natsServerID + `","server_name":"` + natsServerID +
		`","version":"2.10.22","proto":1,"git_commit":"240e9a4","go":"go1.22.8",` +
		`"host":"0.0.0.0","port":4222,"headers":true,"max_payload":1048576,` +
		`"client_id":` + strconv.FormatUint(natsClientID.Add(1), 10) + "}\r\n")
}

var (
	natsPong       = []byte("PONG\r\n")
	natsUnknownErr = []byte("-ERR 'Unknown Protocol Operation'\r\n")
)

// natsOps are the client protocol operations nats-server's parser accepts.
var natsOps = []string{"CONNECT", "PING", "PONG", "PUB", "HPUB", "SUB", "UNSUB", "+OK", "-ERR"}

// NATSFollowUp answers the client's first message after the INFO greeting.
// A message that does not start with a protocol operation (scanners send a
// bare "\r\n\r\n") gets nats-server's parse error, after which the server
// closes the connection. A PING line gets PONG; other operations (CONNECT,
// SUB, PUB with verbose off) get no reply.
func NATSFollowUp(data []byte) (Response, bool) {
	upper := bytes.ToUpper(data)
	known := false
	for _, op := range natsOps {
		if bytes.HasPrefix(upper, []byte(op)) {
			known = true
			break
		}
	}
	if !known {
		return Response{Name: "nats-err", Data: natsUnknownErr, Close: true}, true
	}
	for _, line := range bytes.Split(upper, []byte("\n")) {
		if string(bytes.TrimRight(line, "\r")) == "PING" {
			return Response{Name: "nats-pong", Data: natsPong}, true
		}
	}
	return Response{Name: "nats", NoReply: true}, true
}
