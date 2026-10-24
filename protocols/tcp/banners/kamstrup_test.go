package banners

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var kmpTestStart = time.Date(2026, 10, 24, 20, 0, 0, 0, time.UTC)

// testMeter reads 18432.7 kWh import, 1.2 kWh export and 230 V at start.
func testMeter() *kmpMeter {
	return &kmpMeter{
		start:  kmpTestStart,
		imp:    184327000,
		exp:    12000,
		loadW:  360,
		jitter: func(int) int { return 4 },
	}
}

func TestKMPAnswerShodanSweep(t *testing.T) {
	// Shodan, Ochi event 66cc9166-1cdd-4596-9d6a-c92c291fbc4a (tcp/1025)
	for _, tc := range []struct {
		req, reply string
	}{
		{"803f1001000155a10d", "403f1000010204410002d00771ea0d"},
		{"803f1001000265c20d", "403f1000020204410000000c73b30d"},
		// register 0x000d is stuffed as 1b f2 in the request and the reply
		{"803f1001001bf2942d0d", "403f10001bf20204440afc9b58a9de0d"},
		// three frames pipelined in one segment
		{
			"803f1001000ea44e0d803f1001041e7abb0d803f1001041f6a9a0d",
			"403f10000e02044400002ee058180d403f10041e21020000e6d8660d403f10041f21020000e69dc60d",
		},
	} {
		resp, ok := kmpAnswer(testMeter(), mustHex(tc.req), kmpTestStart)
		require.True(t, ok, tc.req)
		require.Equal(t, Response{Name: "kamstrup-getregister", Data: mustHex(tc.reply)}, resp, tc.req)
	}
}

func TestKMPAnswerRegisters(t *testing.T) {
	m := testMeter()

	// two registers in one request
	resp, ok := kmpAnswer(m, mustHex("803f10020001041e85680d"), kmpTestStart)
	require.True(t, ok)
	require.Equal(t, mustHex("403f1000010204410002d007041e21020000e6b8be0d"), resp.Data)

	// an unknown register is left out of the reply
	resp, ok = kmpAnswer(m, mustHex("803f1001009957100d"), kmpTestStart)
	require.True(t, ok)
	require.Equal(t, Response{Name: "kamstrup-getregister", Data: mustHex("403f10079a0d")}, resp)

	// import grows with the load: 360 W for an hour is 0.36 kWh
	later := kmpTestStart.Add(time.Hour)
	require.Equal(t, uint64(184330), m.value(0x0001, later))
	require.Equal(t, uint64(184330600), m.value(0x000d, later))
	require.Equal(t, uint64(12), m.value(0x0002, later))
}

func TestKMPAnswerLogin(t *testing.T) {
	// login with the Metertool default PIN 12345 is denied and recorded
	resp, ok := kmpAnswer(testMeter(), mustHex("803f9230394cb10d"), kmpTestStart)
	require.True(t, ok)
	require.Equal(t, Response{Name: "kamstrup-login", Data: mustHex("403f9201873c0d"), Password: "12345"}, resp)
}

func TestKMPAnswerNoReply(t *testing.T) {
	for _, req := range []string{
		"80011001000196e70d", // another meter address
		"803f1101000123150d", // unsupported command
	} {
		resp, ok := kmpAnswer(testMeter(), mustHex(req), kmpTestStart)
		require.True(t, ok, req)
		require.Equal(t, Response{Name: "kamstrup", NoReply: true}, resp, req)
	}
}

func TestKMPRejects(t *testing.T) {
	for _, req := range []string{
		"803f1001000155a20d",                 // bad CRC
		"803f1001000155a1",                   // no stop byte
		"803f1001000155a10d00",               // trailing byte
		"3f1001000155a10d",                   // no start byte
		"803f1b0d",                           // escape before the stop byte
		"80550d",                             // too short
		"803f1001000155a10d803f10010002650d", // second frame with bad CRC
	} {
		_, ok := kmpAnswer(testMeter(), mustHex(req), kmpTestStart)
		require.False(t, ok, req)
	}
}

func TestForPayloadKamstrup(t *testing.T) {
	resp, ok := ForPayload(mustHex("803f1001000155a10d"))
	require.True(t, ok)
	require.Equal(t, "kamstrup-getregister", resp.Name)
	frames := resp.Data
	require.Equal(t, byte(kmpResponseStart), frames[0])
	require.Equal(t, byte(kmpStop), frames[len(frames)-1])
	require.Equal(t, mustHex("403f1000010204"), frames[:7])
}

func TestKMPFrameStuffsCRC(t *testing.T) {
	// the CRC of this reply is 7f 80, so its 0x80 is stuffed
	require.Equal(t, mustHex("403f10000e02044400000000"+"1b7fdf"+"0d"),
		kmpFrame(mustHex("3f10000e02044400000000")))
}
