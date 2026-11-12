package banners

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// shodanQueryTypeBody is the plist Shodan sent to tcp/62078
// (run-1794504358-1.jsonl events #5 and #6, 300 bytes with the prefix).
const shodanQueryTypeBody = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>iTunesHelper</string>
    <key>Request</key>
    <string>QueryType</string>
</dict>
</plist>`

func TestLockdownQueryType(t *testing.T) {
	probe := lockdownFrame([]byte(shodanQueryTypeBody))
	require.Len(t, probe, 300)
	require.Equal(t, []byte{0x00, 0x00, 0x01, 0x28}, probe[:4])

	resp, ok := ForPayload(probe)
	require.True(t, ok)
	require.Equal(t, "lockdownd-querytype", resp.Name)
	require.False(t, resp.Close)
	require.Equal(t, int(binary.BigEndian.Uint32(resp.Data)), len(resp.Data)-4)
	body := resp.Data[4:]
	require.True(t, bytes.HasPrefix(body, []byte(`<?xml version="1.0" encoding="UTF-8"?>`)))
	require.Contains(t, string(body), "<key>Request</key>\n\t<string>QueryType</string>")
	require.Contains(t, string(body), "<key>Type</key>\n\t<string>com.apple.mobile.lockdown</string>")

	for name, other := range map[string][]byte{
		"length too long": append([]byte{0x00, 0x00, 0x01, 0x29}, shodanQueryTypeBody...),
		"no prefix":       []byte(shodanQueryTypeBody),
		"other request":   lockdownFrame(bytes.Replace([]byte(shodanQueryTypeBody), []byte("QueryType"), []byte("GetValue"), 1)),
		"not a plist":     lockdownFrame([]byte("<key>Request</key><string>QueryType</string>")),
		"short":           {0x00, 0x00},
	} {
		resp, ok := ForPayload(other)
		require.False(t, ok && resp.Name == "lockdownd-querytype", name)
	}

	resp, ok = ForPort(62078)
	require.True(t, ok)
	require.Equal(t, "lockdownd", resp.Name)
	require.True(t, resp.Silent)
	require.False(t, resp.ServerFirst || resp.GreetWhenIdle)
}
