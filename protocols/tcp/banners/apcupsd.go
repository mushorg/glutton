package banners

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"time"
)

// apcupsd's Network Information Server (tcp/3551) frames every message with a
// 2-byte big-endian length. A client sends "status" in one frame; the server
// answers one frame per "KEY      : value\n" line and ends with a zero-length
// frame. The layout follows apcupsd 3.14 (Back-UPS ES, USB driver).

var apcupsdStatusRequest = []byte{0x00, 0x06, 's', 't', 'a', 't', 'u', 's'}

// apcupsdIdentity is the UPS identity in the status reply. It is drawn once
// per run, so sensors do not share a serial number or host name.
type apcupsdIdentity struct {
	hostname string
	serial   string
	started  time.Time
}

var apcupsdUPS = newApcupsdIdentity()

func newApcupsdIdentity() apcupsdIdentity {
	return apcupsdIdentity{
		hostname: fmt.Sprintf("ups%02d", 1+rand.IntN(9)),
		serial:   fmt.Sprintf("3B%04dX%05d", 1100+rand.IntN(300), rand.IntN(100000)),
		started:  now().Add(-time.Duration(48+rand.IntN(24*60)) * time.Hour),
	}
}

// isApcupsdStatus reports whether data is exactly a NIS "status" request.
func isApcupsdStatus(data []byte) bool {
	return bytes.Equal(data, apcupsdStatusRequest)
}

// apcupsdStatus builds the framed status reply.
func apcupsdStatus(id apcupsdIdentity) []byte {
	const stamp = "2006-01-02 15:04:05 -0700  "
	t := now()
	lines := []string{
		"APC      : 001,036,0879",
		"DATE     : " + t.Format(stamp),
		"HOSTNAME : " + id.hostname,
		"VERSION  : 3.14.14 (31 May 2016) debian",
		"UPSNAME  : " + id.hostname,
		"CABLE    : USB Cable",
		"DRIVER   : USB UPS Driver",
		"UPSMODE  : Stand Alone",
		"STARTTIME: " + id.started.Format(stamp),
		"MODEL    : Back-UPS ES 700G ",
		"STATUS   : ONLINE ",
		"LINEV    : 230.0 Volts",
		"LOADPCT  : 14.0 Percent",
		"BCHARGE  : 100.0 Percent",
		"TIMELEFT : 48.2 Minutes",
		"MBATTCHG : 5 Percent",
		"MINTIMEL : 3 Minutes",
		"MAXTIME  : 0 Seconds",
		"SENSE    : Medium",
		"LOTRANS  : 088.0 Volts",
		"HITRANS  : 139.0 Volts",
		"ALARMDEL : 30 Seconds",
		"BATTV    : 13.6 Volts",
		"LASTXFER : No transfers since turnon",
		"NUMXFERS : 0",
		"TONBATT  : 0 Seconds",
		"CUMONBATT: 0 Seconds",
		"XOFFBATT : N/A",
		"SELFTEST : NO",
		"STATFLAG : 0x05000008",
		"SERIALNO : " + id.serial + "  ",
		"BATTDATE : 2012-04-08",
		"NOMINV   : 230 Volts",
		"NOMBATTV : 12.0 Volts",
		"FIRMWARE : 871.O3 .I USB FW:O3",
		"END APC  : " + t.Format(stamp),
	}
	var out []byte
	for _, l := range lines {
		out = binary.BigEndian.AppendUint16(out, uint16(len(l)+1))
		out = append(out, l...)
		out = append(out, '\n')
	}
	return append(out, 0x00, 0x00)
}
