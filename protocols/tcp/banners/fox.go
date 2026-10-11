package banners

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strconv"
)

// Niagara Fox (Tridium Niagara AX/N4, tcp/1911) is a line-oriented text
// protocol: a header line "fox <a|c|r> <msg id> <reply id> <channel> <command>",
// then a "{ ... };;" block of name=type:value fields. A client opens with a
// hello and the station answers with its own hello describing the host.

// foxBog is the empty BOG facets document Niagara stations send in sys.info.
const foxBog = "<bog version=\"1.0\">\n<p m=\"b=baja\" t=\"b:Facets\" v=\"\"/>\n</bog>\n"

// foxStation is the station identity in the hello reply. It is drawn once per
// run, so sensors do not share a hostId or vmUuid.
type foxStation struct {
	connID  int    // the station's id field
	octet   byte   // last octet of the reported LAN address
	hostID  string // Qnx-XXXX-XXXX-XXXX-XXXX
	vmUUID  string
	station string
}

// foxIdentity is replaced in tests for a stable hello reply.
var foxIdentity = newFoxStation()

func newFoxStation() foxStation {
	var b [36]byte
	_, _ = rand.Read(b[:])
	const alnum = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	id := make([]byte, 16)
	for i := range id {
		id[i] = alnum[int(b[i])%len(alnum)]
	}
	u := b[16:32]
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	return foxStation{
		connID:  1000 + int(b[32])*256 + int(b[33]),
		octet:   20 + b[34]%200,
		hostID:  fmt.Sprintf("Qnx-%s-%s-%s-%s", id[0:4], id[4:8], id[8:12], id[12:16]),
		vmUUID:  fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]),
		station: "JACE_" + strconv.Itoa(1+int(b[35])%12),
	}
}

// isFoxHello reports whether data starts with a Fox hello request header,
// "fox a <n> -1 fox hello".
func isFoxHello(data []byte) bool {
	line, _, ok := bytes.Cut(data, []byte("\n"))
	if !ok {
		return false
	}
	f := bytes.Fields(line)
	if len(f) != 6 || string(f[0]) != "fox" || string(f[1]) != "a" ||
		string(f[3]) != "-1" || string(f[4]) != "fox" || string(f[5]) != "hello" {
		return false
	}
	_, err := strconv.Atoi(string(f[2]))
	return err == nil
}

// foxHello is a Niagara AX 3.8 JACE (QNX) station's hello reply.
func foxHello(s foxStation) []byte {
	addr := "192.168.1." + strconv.Itoa(int(s.octet))
	return []byte("fox a 0 -1 fox hello\n{\n" +
		"fox.version=s:1.0\n" +
		"id=i:" + strconv.Itoa(s.connID) + "\n" +
		"hostName=s:" + addr + "\n" +
		"hostAddress=s:" + addr + "\n" +
		"app.name=s:Station\n" +
		"app.version=s:3.8.311\n" +
		"vm.name=s:Java HotSpot(TM) Embedded Client VM\n" +
		"vm.version=s:25.141-b06\n" +
		"os.name=s:QNX\n" +
		"os.version=s:6.5.0\n" +
		"station.name=s:" + s.station + "\n" +
		"lang=s:en\n" +
		"timeZone=s:America/New_York;-18000000;3600000;02:00:00.000,wall,march,8,on or after,sunday,undefined;02:00:00.000,wall,november,1,on or after,sunday,undefined\n" +
		"hostId=s:" + s.hostID + "\n" +
		"vmUuid=s:" + s.vmUUID + "\n" +
		"brandId=s:vykon\n" +
		"sys.info=o:bog " + strconv.Itoa(len(foxBog)) + "[" + foxBog + "]\n" +
		"};;\n")
}
