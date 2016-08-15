package glutton

import (
	"fmt"
	"github.com/hectane/go-nonblockingchan"
	"honnef.co/go/netdb"
	"os"
)

// getProtocol(80, "tcp")
func getProtocol(port int, transport string) *netdb.Servent {
	prot := netdb.GetProtoByName(transport)
	return netdb.GetServByPort(port, prot)
}

// CheckError handles errors
func CheckError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "Fatal error ", err.Error())
		os.Exit(1)
	}
}

//return Destination port
func getDesport(packetInfo []string, channel *nbc.NonBlockingChan) int {
	//Receiving conntrack logs from channel
	stream, ok := <-channel.Recv
	var connInfo []string
	for ok {
		connInfo = stream.([]string)

		if connInfo[2] == packetInfo[0] && connInfo[4] == packetInfo[1] {
			dport, _ := strconv.Atoi(connInfo[5])
			return dport
		} else {
			stream, ok = <-channel.Recv
		}
	}
	if !ok {
		return -1
	}
	return -1
}
