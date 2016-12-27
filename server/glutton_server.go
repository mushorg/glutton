package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hectane/go-nonblockingchan"
	"github.com/mushorg/glutton"
	"github.com/mushorg/glutton/logger"
)

func localAddresses() {
	log.Println("Listening on the following interfaces:")
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
				log.Printf("\t%v : %s (%s)\n", i.Name, v, v.IP.DefaultMask())
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
	confPath := flag.String("conf", "/etc/glutton/ports.yml", "Config path.")
	setTables := flag.Bool("set-tables", false, "True to set iptables rules")
	capturePackets := flag.Bool("capture-packets", false, "True store pcap data")
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
	log.SetOutput(io.MultiWriter(f, os.Stdout))

	// Channel for tcp logging
	tcpCh := nbc.New()
	//Channel for udp logging
	udpCh := nbc.New()

	// Load config file for remote services
	glutton.LoadPorts(*confPath)

	var wg sync.WaitGroup

	if *capturePackets {
		log.Println("Starting Packet Capturing...")
		wg.Add(1)
		go logger.FindDevice(&wg)
	}

	wg.Add(1)
	go glutton.MonitorTCPConnections(tcpCh, &wg)
	log.Println("Initializing TCP connections tracking..")
	// Delay required for initialization of conntrack modules
	time.Sleep(3 * time.Second)

	wg.Add(1)
	go glutton.MonitorUDPConnections(udpCh, &wg)
	log.Println("Initializing UDP connections tracking...")
	// Delay required for initialization of conntrack modules
	time.Sleep(3 * time.Second)

	log.Println("Starting TCP Server...")
	wg.Add(1)
	go glutton.TCPListener(tcpCh, &wg)

	log.Println("Starting UDP Server...")
	wg.Add(1)
	go glutton.UDPListener(udpCh, &wg)

	wg.Wait()
}
