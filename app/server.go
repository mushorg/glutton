package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/kung-foo/freki"
	"github.com/mushorg/glutton"
)

var logger = log.New()
var client = &http.Client{}

func onErrorExit(err error) {
	if err != nil {
		logger.Fatal(err)
	}
}

func onErrorClose(err error, conn net.Conn) {
	if err != nil {
		logger.Error(err)
		err = conn.Close()
		if err != nil {
			logger.Error(err)
		}
	}
}

func logGollum(rawConn, host, port, dstPort, sensorID, rule string) (err error) {
	conn, err := url.Parse(rawConn)
	if err != nil {
		return
	}
	event := glutton.Event{
		SrcHost:  host,
		SrcPort:  port,
		DstPort:  dstPort,
		SensorID: sensorID,
		Rule:     rule,
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", conn.Scheme+"://"+conn.Host, bytes.NewBuffer(data))
	if err != nil {
		return
	}
	password, _ := conn.User.Password()
	req.SetBasicAuth(conn.User.Username(), password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	logger.Debugf("[gollum  ] response: %s", resp.Status)
	return
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
	connectGollum := flag.String("gollum", "http://gollum:gollum@localhost:9000", "Gollum connection string")
	flag.Parse()

	// Write log to file and stdout
	f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Out = io.MultiWriter(f, os.Stdout)
	if *enableDebug == true {
		logger.Level = log.DebugLevel
	}
	logger.Formatter = &log.TextFormatter{ForceColors: true}
	// Loading and parsing the rules
	logger.Infof("[glutton ] Loading rules from: %s", *rulesPath)
	rulesFile, err := os.Open(*rulesPath)
	onErrorExit(err)
	rules, err := freki.ReadRulesFromFile(rulesFile)
	onErrorExit(err)
	logger.Infof("[glutton ] Rules: %+v", rules)

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
		logger.Debugf("[glutton ] shutting down...")
		onErrorExit(processor.Shutdown())
	}

	defer exit()
	onInterruptSignal(func() {
		exit()
		os.Exit(0)
	})

	gtn, err := glutton.New()
	onErrorExit(err)
	gtn.Logger = logger

	// This is the main listener for rewritten package
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

				if *connectGollum != "" {
					err = logGollum(*connectGollum, host, port, md.TargetPort.String(), gtn.ID.String(), md.Rule.String())
					if err != nil {
						log.Error(err)
					}
				}

				if md.Rule.Name == "telnet" {
					go gtn.HandleTelnet(conn)
				} else if md.TargetPort == 25 {
					go gtn.HandleSMTP(conn)
				} else if md.TargetPort == 3389 {
					go gtn.HandleRDP(conn)
				} else if md.TargetPort == 445 {
					go gtn.HandleSMB(conn)
				} else if md.TargetPort == 21 {
					go gtn.HandleFTP(conn)
				} else if md.TargetPort == 5060 {
					go gtn.HandleSIP(conn)
				} else if md.TargetPort == 5900 {
					go gtn.HandleRFB(conn)
				} else {
					snip, bufConn, err := gtn.Peek(conn, 4)
					onErrorClose(err, conn)
					httpMap := map[string]bool{"GET ": true, "POST": true, "HEAD": true, "OPTI": true}
					if _, ok := httpMap[strings.ToUpper(string(snip))]; ok == true {
						go gtn.HandleHTTP(bufConn)
					} else {
						go gtn.HandleTCP(bufConn)
					}
				}
			}(conn)
		}
	}()

	onErrorExit(processor.Start())
}
