package glutton

import (
	. "fmt"
	"github.com/hectane/go-nonblockingchan"
	"honnef.co/go/netdb"
	"os"
	"strconv"
	"time"
)

// getProtocol(80, "tcp")
func GetProtocol(port int, transport string) *netdb.Servent {
	prot := netdb.GetProtoByName(transport)
	return netdb.GetServByPort(port, prot)
}

// CheckError handles errors
func CheckError(err error) {
	if err != nil {
		Fprintln(os.Stderr, "Fatal error ", err.Error())
		os.Exit(1)
	}
}

//return Destination port for TCP
func GetTCPDesPort(p []string, ch *nbc.NonBlockingChan) int {

	if ch.Len() == 0 {
		time.Sleep(10000000 * time.Nanosecond)
		if ch.Len() == 0 {
			Println("[TCP]  Channel is empty!")
			return -1
		}
	}

	// Receiving conntrack logs from channel
	stream, ok := <-ch.Recv

	for ok {
		c, flag := stream.([]string)
		if !flag {
			Println("[TCP] Invalid log! glutton.go: stream.([]string) failed.")
			stream, ok = <-ch.Recv
			continue
		}

		if c[1] == p[0] && c[3] == p[1] {

			dp, err := strconv.Atoi(c[4])
			if err != nil {
				Println("[TCP] Invalid destination port! glutton.go strconv.Atoi()")
				return -1
			}

			return dp
		} else {
			if ch.Len() == 0 {
				Println("[TCP] No logs found!")
				return -1
			}
			stream, ok = <-ch.Recv
		}

	}

	return -1
}

//return Destination port for UDP
func GetUDPDesPort(p []string, ch *nbc.NonBlockingChan) int {

	if ch.Len() == 0 {
		time.Sleep(10000000 * time.Nanosecond)
		if ch.Len() == 0 {
			Println("[UDP] Channel is empty!")
			return -1
		}
	}

	// Receiving conntrack logs from channel
	stream, ok := <-ch.Recv

	for ok {
		c, flag := stream.([]string)
		if !flag {
			Println("[UDP] Invalid log! glutton.go: stream.([]string) failed.")
			stream, ok = <-ch.Recv
			continue
		}
		if c[2] == p[0] && c[4] == p[1] {
			dp, err := strconv.Atoi(c[5])
			if err != nil {
				Println("[UDP] Invalid destination port! glutton.go strconv.Atoi() ")
				return -1
			}
			return dp
		} else {

			if ch.Len() == 0 {
				Println("[UDP] No logs found!")
				return -1
			}
			stream, ok = <-ch.Recv
		}

	}

	return -1
}
