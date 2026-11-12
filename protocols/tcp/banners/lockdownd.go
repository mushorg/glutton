package banners

import (
	"bytes"
	"encoding/binary"
	"regexp"
)

// Apple lockdownd (tcp/62078, nmap-services iphone-sync) frames every message
// as a big-endian u32 length followed by a property list. A client starts
// with a QueryType request; libimobiledevice's lockdownd_query_type accepts
// the device when the reply's Type is com.apple.mobile.lockdown. Shodan
// (207.90.244.3, 209.38.131.131; run-1794504358-1.jsonl events #5 and #6)
// sends an XML QueryType request with Label iTunesHelper to tcp/62078 and
// hung up after the random-byte reply.
var lockdownQueryType = regexp.MustCompile(`<key>Request</key>\s*<string>QueryType</string>`)

// lockdownQueryTypeReply is the plist body a device sends back, in the tab
// indented layout CoreFoundation writes XML plists in.
var lockdownQueryTypeReply = []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Request</key>
	<string>QueryType</string>
	<key>Type</key>
	<string>com.apple.mobile.lockdown</string>
</dict>
</plist>
`)

// lockdownFrame prefixes body with its big-endian u32 length.
func lockdownFrame(body []byte) []byte {
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(body)), uint32(len(body)))
	return append(out, body...)
}

// isLockdownQueryType reports whether data is one complete length-prefixed
// XML plist carrying Request QueryType.
func isLockdownQueryType(data []byte) bool {
	if len(data) < 4 || int(binary.BigEndian.Uint32(data)) != len(data)-4 {
		return false
	}
	body := data[4:]
	return bytes.HasPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte("<?xml")) &&
		bytes.Contains(body, []byte("<plist")) &&
		lockdownQueryType.Match(body)
}

func lockdownReply(data []byte) (Response, bool) {
	if !isLockdownQueryType(data) {
		return Response{}, false
	}
	return Response{Name: "lockdownd-querytype", Data: lockdownFrame(lockdownQueryTypeReply)}, true
}
