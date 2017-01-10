package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/kung-foo/freki"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
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

func readRules(rulesPath string) (freki.PortRules, error) {
	rules := freki.PortRules{}
	b, err := ioutil.ReadFile(rulesPath)
	onErrorExit(err)
	err = yaml.Unmarshal(b, &rules)
	onErrorExit(err)
	return rules, nil
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
	rulesPath := flag.String("rules", "/etc/glutton/rules.yaml", "Rules path")
	flag.Parse()

	log.Infof("Loading rules from: %s", *rulesPath)
	portRules, err := readRules(*rulesPath)
	onErrorExit(err)
	log.Infof("Rules: %+v", portRules)

	f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	logrus.SetOutput(io.MultiWriter(f, os.Stdout))

	processor := freki.New()
	//processor.SetPortRules(portRules)
	err = processor.Init()
	onErrorExit(err)

	exit := func() {
		err := processor.Stop()
		if err != nil {
			log.Error(err)
		}
		onErrorExit(processor.Cleanup())
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
				conn.SetReadDeadline(time.Now().Add(time.Second * 5))
				host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
				ck := freki.NewConnKeyByString(host, port)
				md := processor.Connections.GetByFlow(ck)
				log.Infof("%s -> %s", host, md.TargetPort)
				if rule, ok := portRules.Ports[int(md.TargetPort)] ok {
					if rule.Target == "telnet" {
						handleTelnet(conn)
					}
				}
				err := conn.Close()
				if err != nil {
					log.Error(err)
				}
			}(conn)
		}
	}()

	processor.Start()
}
