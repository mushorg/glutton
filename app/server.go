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
	logPath := flag.String("log", "/dev/null", "Log path.")
	iface := flag.String("interface", "eth0", "Interface to work with.")
	rulesPath := flag.String("rules", "/etc/glutton/rules.yaml", "Rules path")
	flag.Parse()

	log.Infof("Loading rules from: %s", *rulesPath)
	rulesFile, err := os.Open(*rulesPath)
	rules, err := freki.ReadRulesFromFile(rulesFile)
	onErrorExit(err)
	log.Infof("Rules: %+v", rules)

	f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	log.SetOutput(io.MultiWriter(f, os.Stdout))

	logger := log.New()
	//logger.Level = log.DebugLevel
	processor, err := freki.New(*iface, rules, logger)
	onErrorExit(err)

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
				if md != nil {
					if md.TargetPort == 23 {
						go glutton.HandleTelnet(conn)
					}
				} else {
					err := conn.Close()
					if err != nil {
						log.Error(err)
					}
				}
			}(conn)
		}
	}()

	processor.Start()
}
