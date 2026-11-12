package banners

import "bytes"

// Cisco Smart Install (SMI, tcp/4786) clients ask a switch whether it runs the
// Smart Install director/client service with a 24-byte request of six BE u32
// words. Cisco Talos' smi_check.py sends exactly this request and reports a
// switch as exposed (CVE-2018-0171, CVE-2018-0156) when the reply equals the
// 24 bytes below. The same request arrived on tcp/4786 from 216.25.90.13
// (run-1794504358-1.jsonl event #3) and was answered with random bytes.
var (
	smartInstallProbe = mustHex("000000010000000100000004000000080000000100000000")
	smartInstallReply = mustHex("000000040000000000000003000000080000000100000000")
)

func smartInstallProbeReply(data []byte) (Response, bool) {
	if !bytes.Equal(data, smartInstallProbe) {
		return Response{}, false
	}
	return Response{Name: "smart-install", Data: smartInstallReply}, true
}
