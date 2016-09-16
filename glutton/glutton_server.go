package main

import (
	"flag"
	"github.com/hectane/go-nonblockingchan"
	"github.com/mushorg/glutton"
	"github.com/mushorg/glutton/logger"
	"log"
	"os"
	"time"
)

func main() {
	println("\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
	print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n")
	print("%%													%%\n")
	print("%%		  %%%%%%   %%       %%      %%  %%%%%%%%%%  %%%%%%%%%%    %%%%%     %%%%     %%		%%\n")
	print("%%		%%         %%       %%      %%      %%          %%      %%     %%   %% %%    %%		%%\n")
	print("%%		%%    %%%  %%       %%      %%      %%          %%      %%     %%   %%   %%  %%		%%\n")
	print("%%		 %%%%%%%   %%%%%%%   %%%%%%%        %%          %%        %%%%%     %%     %%%%		%%\n")
	print("%%													%%\n")
	print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n")
	print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n")

	logPath := flag.String("log", "/dev/null", "Log path.")
	flag.Parse()

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
	glutton.LoadServices()

	println("[*] Starting Packet Capturing...")

	go glutton.StartCapturing()

	go logger.FindDevice()

	go glutton.MonitorTCPConnections(tcpCh)
	println("[*] Initializing TCP connections tracking..")
	// Delay required for initialization of conntrack modules
	time.Sleep(3 * time.Second)

	go glutton.MonitorUDPConnections(udpCh)
	println("[*] Initializing UDP connections tracking...")
	// Delay required for initialization of conntrack modules
	time.Sleep(3 * time.Second)

	println("[*] Starting TCP Server...")
	go glutton.TcpListener(f, tcpCh)

	println("[*] Starting UDP Server...")
	glutton.UdpListener(f, udpCh)
}
