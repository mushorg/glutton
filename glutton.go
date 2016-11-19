package glutton

import (
	. "fmt"
	"github.com/hectane/go-nonblockingchan"
	"gopkg.in/yaml.v2"
	"honnef.co/go/netdb"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// For the fields of services.conf
type Config struct {
	Description string
	Ports       map[int]string
}

var ser Config

// Load services.conf file into ser
func LoadServices() {
	f, err := filepath.Abs("/etc/glutton/services.yml")
	CheckError("[*] Error in absolute representation of file LoadServices().", err)

	ymlF, err := ioutil.ReadFile(f)

	if err != nil {
		panic(err)
	}

	err = yaml.Unmarshal(ymlF, &ser)
	if err != nil {
		CheckError("[*] service.yml unmarshal Error.", err)
	}

	if len(ser.Ports) == 0 {
		println("[*] **Host list is empty, Please update services.yml")
		os.Exit(1)
	}
	println("[*] Services loaded successfully....")

}

// Return destination address of the service to redirect traffic
func GetHost(p int) string {
	return ser.Ports[p]
}

//return Destination port for TCP
func GetTCPDesPort(p []string, ch *nbc.NonBlockingChan) int {

	if ch.Len() == 0 {
		time.Sleep(10 * time.Millisecond)
		if ch.Len() == 0 {
			println("[*] TCP Channel is empty!")
			return -1
		}
	}

	// Receiving conntrack logs from channel
	stream, ok := <-ch.Recv

	for ok {
		c, flag := stream.([]string)
		if !flag {
			println("[*] Error. TCP Invalid log! glutton.go: stream.([]string) failed.")
			stream, ok = <-ch.Recv
			continue
		}

		if c[1] == p[0] && c[3] == p[1] {

			dp, err := strconv.Atoi(c[4])
			if err != nil {
				println("[*] Error. TCP Invalid destination port! glutton.go strconv.Atoi()")
				return -1
			}
			return dp
		} else {
			if ch.Len() == 0 {
				println("[*] TCP No logs found!")
				return -1
			}
			stream, ok = <-ch.Recv
		}

	}

	return -1
}

//return Destination port for UDP
func GetUDPDesPort(p []string, ch *nbc.NonBlockingChan) int {

	// Time used by conntrack for UDP logging
	time.Sleep(10 * time.Millisecond)

	if ch.Len() == 0 {
		time.Sleep(10 * time.Millisecond)
		if ch.Len() == 0 {
			println("[*] UDP Channel is empty!")
			return -1
		}
	}

	// Receiving conntrack logs from channel
	stream, ok := <-ch.Recv

	for ok {
		c, flag := stream.([]string)
		if !flag {
			println("[*] Error. UDP Invalid log! glutton.go: stream.([]string) failed.")
			stream, ok = <-ch.Recv
			continue
		}
		if c[2] == p[0] && c[4] == p[1] {
			dp, err := strconv.Atoi(c[5])
			if err != nil {
				println("[*] Error. UDP Invalid destination port! glutton.go strconv.Atoi() ")
				return -1
			}
			return dp
		} else {
			if ch.Len() == 0 {
				println("[*] UDP No logs found!")
				return -1
			}
			stream, ok = <-ch.Recv
		}

	}

	return -1
}

// getProtocol(80, "tcp")
func GetProtocol(port int, transport string) *netdb.Servent {
	prot := netdb.GetProtoByName(transport)
	return netdb.GetServByPort(port, prot)
}

// CheckError handles Fatal errors
func CheckError(message string, err error) {
	if err != nil {
		println(message)
		Fprintln(os.Stderr, "[*] Fatal Error.", err.Error())
		os.Exit(1)
	}
}
