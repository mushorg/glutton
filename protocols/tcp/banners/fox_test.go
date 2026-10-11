package banners

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// foxWorkbenchHello is the Fox hello from Ochi event
// 626c9411-15ee-4235-98de-e8d3c5f3c931 (tcp/1911): a Workbench 3.7.44 client
// with the fixed host fields of nmap's fox-info script.
const foxWorkbenchHello = "fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\nhostName=s:xpvm-0omdc01xmy\nhostAddress=s:192.168.1.125\napp.name=s:Workbench\napp.version=s:3.7.44\nvm.name=s:Java HotSpot(TM) Server VM\nvm.version=s:20.4-b02\nos.name=s:Windows XP\nos.version=s:5.1\nlang=s:en\ntimeZone=s:America/Los_Angeles;-28800000;3600000;02:00:00.000,wall,march,8,on or after,sunday,undefined;02:00:00.000,wall,november,1,on or after,sunday,undefined\nhostId=s:Win-99CB-D49D-5442-07BB\nvmUuid=s:8b530bc8-76c5-4139-a2ea-0fabd394d305\nbrandId=s:vykon\n};;\n"

func stubFox(t *testing.T) foxStation {
	t.Helper()
	prev := foxIdentity
	foxIdentity = foxStation{connID: 4242, octet: 140, hostID: "Qnx-ABCD-0000-1A2B-3C4D",
		vmUUID: "11111111-2222-4333-8444-555555555555", station: "JACE_3"}
	t.Cleanup(func() { foxIdentity = prev })
	return foxIdentity
}

func TestForPayloadFoxHello(t *testing.T) {
	stubFox(t)
	resp, ok := ForPayload([]byte(foxWorkbenchHello))
	require.True(t, ok)
	require.Equal(t, "niagara-fox-hello", resp.Name)
	require.False(t, resp.Silent)
	require.False(t, resp.NoReply)
	require.Equal(t, "fox a 0 -1 fox hello\n{\n"+
		"fox.version=s:1.0\n"+
		"id=i:4242\n"+
		"hostName=s:192.168.1.140\n"+
		"hostAddress=s:192.168.1.140\n"+
		"app.name=s:Station\n"+
		"app.version=s:3.8.311\n"+
		"vm.name=s:Java HotSpot(TM) Embedded Client VM\n"+
		"vm.version=s:25.141-b06\n"+
		"os.name=s:QNX\n"+
		"os.version=s:6.5.0\n"+
		"station.name=s:JACE_3\n"+
		"lang=s:en\n"+
		"timeZone=s:America/New_York;-18000000;3600000;02:00:00.000,wall,march,8,on or after,sunday,undefined;02:00:00.000,wall,november,1,on or after,sunday,undefined\n"+
		"hostId=s:Qnx-ABCD-0000-1A2B-3C4D\n"+
		"vmUuid=s:11111111-2222-4333-8444-555555555555\n"+
		"brandId=s:vykon\n"+
		"sys.info=o:bog 61[<bog version=\"1.0\">\n<p m=\"b=baja\" t=\"b:Facets\" v=\"\"/>\n</bog>\n]\n"+
		"};;\n", string(resp.Data))
}

func TestFoxHelloFields(t *testing.T) {
	out := string(foxHello(newFoxStation()))
	require.True(t, strings.HasSuffix(out, "\n};;\n"))
	require.NotContains(t, out, "\r")
	lower := strings.ToLower(out)
	require.NotContains(t, lower, "glutton")
	require.NotContains(t, lower, "honeypot")
	require.Regexp(t, `\nhostId=s:Qnx-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}\n`, out)
	require.Regexp(t, `\nvmUuid=s:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\n`, out)
	require.Regexp(t, `\nhostAddress=s:192\.168\.1\.([2-9][0-9]|1[0-9]{2}|2[01][0-9])\n`, out)
	require.Regexp(t, `\nstation\.name=s:JACE_([1-9]|1[0-2])\n`, out)
}

func TestIsFoxHello(t *testing.T) {
	require.True(t, isFoxHello([]byte(foxWorkbenchHello)))
	require.True(t, isFoxHello([]byte("fox a 7 -1 fox hello\n{\n};;\n")))
	for _, data := range []string{
		"", "fox a 1 -1 fox hello", // no newline yet
		"fox c 1 -1 fox hello\n",       // not a sync request
		"fox a x -1 fox hello\n",       // id not a number
		"fox a 1 2 fox hello\n",        // a reply, not a request
		"fox a 1 -1 fox hello extra\n", // trailing field
		"fox a 1 -1 fox close\n",       // other command
		"GET / HTTP/1.0\r\n\r\n",       // http
		"FOX A 1 -1 FOX HELLO\n",       // case matters
	} {
		require.False(t, isFoxHello([]byte(data)), "%q", data)
		_, ok := ForPayload([]byte(data))
		require.False(t, ok, "%q", data)
	}
}
