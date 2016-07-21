package glutton

import (
	"fmt"
	"os"

	"honnef.co/go/netdb"
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
