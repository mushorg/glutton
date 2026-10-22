package banners

import (
	"bytes"
	"fmt"
	"math/rand/v2"
)

// Xiongmai-firmware DVRs/NVRs on HiSilicon SoCs run macGuarder/dvrHelper on
// tcp/9530, a backdoor that starts telnetd after a challenge-response
// (disclosed 2020, habr.com/en/post/486856). The client opens with
// "OpenTelnet:OpenOnce" and the device answers "randNum:" plus an 8-digit
// random decimal (the Habr write-up); the client then answers the challenge
// and expects "verify:OK" (Exploit-DB 48004). The challenge is never verified
// here: the answer is recorded without a reply, since a real device's failure
// string is not public.

var xmOpenTelnet = []byte("OpenTelnet:OpenOnce")

// xmRandNum draws the per-connection challenge; replaced in tests.
var xmRandNum = func() string {
	return fmt.Sprintf("%08d", rand.IntN(100000000))
}

// isXiongmaiOpenTelnet reports whether data is the backdoor's opening
// message: bare (as Shodan sends it) or with the 1-byte length prefix the
// public PoC adds, optionally NUL- or newline-terminated.
func isXiongmaiOpenTelnet(data []byte) bool {
	if len(data) > 0 && int(data[0]) == len(data)-1 {
		data = data[1:]
	}
	return bytes.Equal(bytes.TrimRight(data, "\x00\r\n"), xmOpenTelnet)
}

// xiongmaiReply answers "OpenTelnet:OpenOnce" with the randNum challenge.
func xiongmaiReply(data []byte) (Response, bool) {
	if !isXiongmaiOpenTelnet(data) {
		return Response{}, false
	}
	return Response{Name: "xiongmai-randnum", Data: []byte("randNum:" + xmRandNum())}, true
}
