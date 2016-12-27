package glutton

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/hectane/go-nonblockingchan"
	"gopkg.in/yaml.v2"
	"honnef.co/go/netdb"
)

// Config For the fields of ports.conf
type Config struct {
	Default string
	Ports   map[int]string
}

var (
	portConf Config

	src     []string // slice contains attributes of previous packet conntrack logs
	desP    int      // Destination port of previous packet returned to the UDP server
	unknown []string // Address not logged by conntrack
)

// SetIPTables modifies to iptables
func SetIPTables() {
	ipt, err := iptables.New()
	if err != nil {
		panic(err)
	}
	ipt.Append("nat", "PREROUTING", "-p", "tcp", "--dport", "1:5000", "-j", "REDIRECT", "--to-port", "5000")
	ipt.Append("nat", "PREROUTING", "-p", "tcp", "--dport", "5002:65389", "-j", "REDIRECT", "--to-port", "5000")
	ipt.Append("nat", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-port", "5000")
}

// LoadPorts ports.yml file into portConf
func LoadPorts(confPath string) {
	f, err := filepath.Abs(confPath)
	if err != nil {
		log.Println("Error in absolute representation of file LoadPorts().")
		os.Exit(1)
	}
	ymlF, err := ioutil.ReadFile(f)

	if err != nil {
		panic(err)
	}

	err = yaml.Unmarshal(ymlF, &portConf)
	if err != nil {
		CheckError("[*] service.yml unmarshal Error.", err)
	}

	if len(portConf.Ports) == 0 {
		log.Println("Host list is empty, Please update ports.yml")
		os.Exit(1)
	}
	log.Println("Port configuration loaded successfully....")

}

// GetHandler returns destination address of the service to redirect traffic
func GetHandler(p int) string {
	return portConf.Ports[p]
}

// GetDefaultHandler returns the default handler or empty string
func GetDefaultHandler() string {
	return portConf.Default
}

// GetTCPDesPort return Destination port for TCP
func GetTCPDesPort(p []string, ch *nbc.NonBlockingChan) int {
	if ch.Len() == 0 {
		time.Sleep(10 * time.Millisecond)
		if ch.Len() == 0 {
			log.Println("TCP Channel is empty!")
			return -1
		}
	}

	// Receiving conntrack logs from channel
	stream, ok := <-ch.Recv

	for ok {
		c, flag := stream.([]string)
		if !flag {
			log.Println("Error. TCP Invalid log! glutton.go: stream.([]string) failed.")
			stream, ok = <-ch.Recv
			continue
		}

		if c[1] == p[0] && c[3] == p[1] {

			dp, err := strconv.Atoi(c[4])
			if err != nil {
				log.Println("Error. TCP Invalid destination port! glutton.go strconv.Atoi()")
				return -1
			}
			return dp
		}
		if ch.Len() == 0 {
			log.Println("TCP No logs found!")
			return -1
		}
		stream, ok = <-ch.Recv
	}
	return -1
}

// GetUDPDesPort return Destination port for UDP
func GetUDPDesPort(p []string, ch *nbc.NonBlockingChan) int {

	if len(unknown) != 0 {
		if p[0] == unknown[0] && p[1] == unknown[1] {
			return -1
		}
	}

	if len(src) != 0 {
		if src[2] == p[0] && src[4] == p[1] {
			return desP
		}
	}

	// Time used by conntrack for UDP logging
	time.Sleep(10 * time.Millisecond)

	if ch.Len() == 0 {
		time.Sleep(10 * time.Millisecond)
		if ch.Len() == 0 {
			log.Println("UDP Channel is empty!")
			return -1
		}
	}

	// Receiving conntrack logs from channel
	stream, ok := <-ch.Recv
	if ok {
		c, flag := stream.([]string)
		if !flag {
			log.Println("Error. UDP Invalid log! glutton.go: stream.([]string) failed.")
			return -1
		}

		if c[2] == p[0] && c[4] == p[1] {
			d, err := strconv.Atoi(c[5])
			if err != nil {
				log.Println("Error. UDP Invalid destination port! glutton.go strconv.Atoi() ")
				return -1
			}
			unknown = make([]string, 0)
			src = c
			desP = d
			return d
		}
		unknown = p
	}
	return -1
}

// GetProtocol (80, "tcp")
func GetProtocol(port int, transport string) *netdb.Servent {
	prot := netdb.GetProtoByName(transport)
	return netdb.GetServByPort(port, prot)
}
