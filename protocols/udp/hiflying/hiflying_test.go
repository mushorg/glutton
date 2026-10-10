package hiflying

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	for name, tc := range map[string]struct {
		in      string
		command string
		args    string
		hasArgs bool
		masked  string
	}{
		"discovery":        {"HF-A11ASSISTHREAD", "DISCOVER", "", false, ""},
		"discovery crlf":   {"HF-A11ASSISTHREAD\r\n", "DISCOVER", "", false, ""},
		"enter at":         {"+ok", "ENTER_AT", "", false, ""},
		"query":            {"AT+VER\r", "AT+VER", "", false, ""},
		"lower case":       {"at+wsssid\r\n", "AT+WSSSID", "", false, ""},
		"set":              {"AT+UPURL=http://example.invalid/fw.bin\r", "AT+UPURL", "http://example.invalid/fw.bin", true, ""},
		"set wskey":        {"AT+WSKEY=WPA2PSK,AES,hunter22\r", "AT+WSKEY", "WPA2PSK,AES,***", true, "AT+WSKEY=WPA2PSK,AES,***\r"},
		"set aswd":         {"AT+ASWD=secret\r", "AT+ASWD", "***", true, "AT+ASWD=***\r"},
		"set webu":         {"AT+WEBU=admin,pass\r", "AT+WEBU", "admin,***", true, "AT+WEBU=admin,***\r"},
		"wskey no key":     {"AT+WSKEY=OPEN,NONE\r", "AT+WSKEY", "OPEN,NONE", true, ""},
		"only first line":  {"AT+VER\rAT+Z\r", "AT+VER", "", false, ""},
		"empty":            {"", "UNKNOWN", "", false, ""},
		"bare prefix":      {"AT+", "UNKNOWN", "", false, ""},
		"bad verb":         {"AT+V ER\r", "UNKNOWN", "", false, ""},
		"other password":   {"WIFIKIT-214028-READ", "UNKNOWN", "", false, ""},
		"modem at":         {"AT\r", "UNKNOWN", "", false, ""},
		"long verb":        {"AT+ABCDEFGHIJKLMNOPQ\r", "UNKNOWN", "", false, ""},
		"discovery prefix": {"HF-A11ASSISTHREADX", "UNKNOWN", "", false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			r := Parse([]byte(tc.in))
			require.Equal(t, tc.command, r.Command())
			require.Equal(t, tc.args, r.Args)
			require.Equal(t, tc.hasArgs, r.HasArgs)
			if tc.masked == "" {
				require.Nil(t, r.Masked)
			} else {
				require.Equal(t, tc.masked, string(r.Masked))
			}
		})
	}
}

func TestLooksLike(t *testing.T) {
	require.True(t, LooksLikeDiscovery([]byte(DiscoveryPassword)))
	require.True(t, LooksLikeDiscovery([]byte(DiscoveryPassword+"\r\n")))
	require.False(t, LooksLikeDiscovery([]byte(DiscoveryPassword+"\r\nAT+VER\r")))
	require.False(t, LooksLikeDiscovery([]byte("HF-A11")))
	require.True(t, LooksLikeCommand([]byte("+ok")))
	require.True(t, LooksLikeCommand([]byte("AT+WSKEY\r")))
	require.False(t, LooksLikeCommand([]byte("GET / HTTP/1.1\r\n")))
	require.False(t, LooksLikeCommand([]byte(DiscoveryPassword)))
}

func TestModuleForIsStable(t *testing.T) {
	a, b := ModuleFor([]byte("198.51.100.1")), ModuleFor([]byte("198.51.100.1"))
	require.Equal(t, a, b)
	require.NotEqual(t, a.MAC, ModuleFor([]byte("198.51.100.2")).MAC)
	require.Equal(t, [3]byte{0xac, 0xcf, 0x23}, [3]byte(a.MAC[:3]))
	require.True(t, a.IP.IsPrivate())
	require.Len(t, a.Key, 10)
}

func TestBuildDiscoveryReply(t *testing.T) {
	m := Module{IP: []byte{192, 168, 1, 123}, MAC: [6]byte{0xac, 0xcf, 0x23, 0x01, 0xab, 0xff}}
	require.Equal(t, "192.168.1.123,ACCF2301ABFF,HF-LPB100", string(BuildDiscoveryReply(m)))
}

func TestBuildATReply(t *testing.T) {
	m := Module{
		IP: []byte{192, 168, 1, 123}, Gateway: []byte{192, 168, 1, 1},
		MAC: [6]byte{0xac, 0xcf, 0x23, 1, 2, 3}, APMAC: [6]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60},
		SSID: "TP-Link_ABCD", Key: "0123456789",
	}
	for in, want := range map[string]struct{ resp, status string }{
		"AT+VER\r":          {"+ok=1.0.06a-14 (2015-09-08 10:20 1M)\r\n\r\n", StatusOK},
		"AT+MID\r":          {"+ok=HF-LPB100\r\n\r\n", StatusOK},
		"AT+WSSSID\r":       {"+ok=TP-Link_ABCD\r\n\r\n", StatusOK},
		"AT+WSKEY\r":        {"+ok=WPA2PSK,AES,0123456789\r\n\r\n", StatusOK},
		"AT+WSLK\r":         {"+ok=TP-Link_ABCD(102030405060)\r\n\r\n", StatusOK},
		"AT+WANN\r":         {"+ok=DHCP,192.168.1.123,255.255.255.0,192.168.1.1\r\n\r\n", StatusOK},
		"AT+WSMAC\r":        {"+ok=ACCF23010203\r\n\r\n", StatusOK},
		"AT+Q\r":            {"+ok\r\n\r\n", StatusOK},
		"AT+RELD\r":         {"+ok=rebooting...\r\n\r\n", StatusOK},
		"AT+WSSSID=evil\r":  {"+ok\r\n\r\n", StatusOK},
		"AT+UPURL=x\r":      {"+ok\r\n\r\n", StatusOK},
		"AT+VER=1\r":        {"+ERR=-2\r\n\r\n", StatusErr},
		"AT+NOPE\r":         {"+ERR=-2\r\n\r\n", StatusErr},
		"HF-A11ASSISTHREAD": {"+ERR=-2\r\n\r\n", StatusErr},
	} {
		resp, status := BuildATReply(m, Parse([]byte(in)))
		require.Equal(t, want.resp, string(resp), in)
		require.Equal(t, want.status, status, in)
	}
}
