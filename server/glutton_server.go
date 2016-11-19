package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/hectane/go-nonblockingchan"
	"github.com/mushorg/glutton"
)

func localAddresses() {
	println("[*] Listening on the following interfaces:")
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				fmt.Printf("\t%v : %s (%s)\n", i.Name, v, v.IP.DefaultMask())
			}
		}
	}
}

func main() {
	fmt.Println(`
	    _____ _       _   _
	   / ____| |     | | | |
	  | |  __| |_   _| |_| |_ ___  _ __
	  | | |_ | | | | | __| __/ _ \| '_ \
	  | |__| | | |_| | |_| || (_) | | | |
	   \_____|_|\__,_|\__|\__\___/|_| |_|

	`)

	logPath := flag.String("log", "/dev/null", "Log path.")
	confPath := flag.String("conf", "/etc/glutton/proxy.yml", "Config path.")
	setTables := flag.Bool("set-tables", false, "True to set iptables rules")
	flag.Parse()

	localAddresses()

	if *setTables {
		glutton.SetIPTables()
	}

	// Setup file logging
	f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	log.SetOutput(f)

	// Channel for tcp logging
	tcpCh := nbc.New()
	//Channel for udp logging
	udpCh := nbc.New()

	// Load config file for remote services
	glutton.LoadPorts(*confPath)

	go glutton.MonitorTCPConnections(tcpCh)
	println("[*] Initializing TCP connections tracking..")
	// Delay required for initialization of conntrack modules
	time.Sleep(3 * time.Second)

	go glutton.MonitorUDPConnections(udpCh)
	println("[*] Initializing UDP connections tracking...")
	// Delay required for initialization of conntrack modules
	time.Sleep(3 * time.Second)

	println("[*] Starting TCP Server...")
	go glutton.TCPListener(f, tcpCh)

	println("[*] Starting UDP Server...")
	glutton.UDPListener(f, udpCh)
}
