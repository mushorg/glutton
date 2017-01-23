package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/kung-foo/freki"
	"github.com/mushorg/glutton"
)

func onErrorExit(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func onErrorClose(err error, conn net.Conn) {
	if err != nil {
		log.Error(err)
		err = conn.Close()
		if err != nil {
			log.Error(err)
		}
	}
}

func onInterruptSignal(fn func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		fn()
	}()
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
	logPath := flag.String("log", "/dev/null", "Log path")
	iface := flag.String("interface", "eth0", "Interface to work with")
	rulesPath := flag.String("rules", "/etc/glutton/rules.yaml", "Rules path")
	enableDebug := flag.Bool("debug", false, "Set to enable debug log")
	flag.Parse()

	log.Infof("[glutton ] Loading rules from: %s", *rulesPath)
	rulesFile, err := os.Open(*rulesPath)
	rules, err := freki.ReadRulesFromFile(rulesFile)
	onErrorExit(err)
	log.Infof("[glutton ] Rules: %+v", rules)

	// Write log to file and stdout
	f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	onErrorExit(err)
	log.SetOutput(io.MultiWriter(f, os.Stdout))

	logger := log.New()
	if *enableDebug == true {
		logger.Level = log.DebugLevel
	}

	// Initiate the freki processor
	processor, err := freki.New(*iface, rules, logger)
	onErrorExit(err)
	// Adding a proxy server
	processor.AddServer(freki.NewTCPProxy(6000))

	err = processor.Init()
	onErrorExit(err)

	exitMtx := sync.RWMutex{}
	exit := func() {
		exitMtx.Lock()
		println() // make it look nice after the ^C
		onErrorExit(processor.Shutdown())
		os.Exit(0)
	}

	defer exit()
	onInterruptSignal(exit)

	go func() {
		ln, err := net.Listen("tcp", ":5000")
		onErrorExit(err)

		for {
			conn, err := ln.Accept()
			onErrorExit(err)

			go func(conn net.Conn) {
				// TODO: Figure out how this works.
				//conn.SetReadDeadline(time.Now().Add(time.Second * 5))
				host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
				ck := freki.NewConnKeyByString(host, port)
				md := processor.Connections.GetByFlow(ck)

				logger.Debugf("[glutton ] new connection: %s:%s -> %d", host, port, md.TargetPort)

				if md.Rule.Name == "telnet" {
					go glutton.HandleTelnet(conn)
				} else if md.TargetPort == 25 {
					go glutton.HandleSMTP(conn)
				} else if md.TargetPort == 5900 {
					go glutton.HandleRFB(conn)
				} else {
					snip, bufConn, err := glutton.Peek(conn, 4)
					onErrorClose(err, conn)
					httpMap := map[string]bool{"GET ": true, "POST": true, "HEAD": true}
					if _, ok := httpMap[string(snip)]; ok == true {
						go glutton.HandleHTTP(bufConn)
					} else {
						go glutton.HandleTCP(conn)
					}
				}
			}(conn)
		}
	}()

	processor.Start()
}
