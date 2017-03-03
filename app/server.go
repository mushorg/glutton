package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/kung-foo/freki"
	"github.com/mushorg/glutton"
)

func onErrorExit(err error) {
	if err != nil {
		log.Fatalf("[glutton ] %+v", err)
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
	logger := log.New()

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

	// Initiate glutton
	gtn, err := glutton.New(processor, logger, rules, connectGollum)
	onErrorExit(err)
	go gtn.Start()

	err = processor.Init()
	onErrorExit(err)

	exitMtx := sync.RWMutex{}
	exit := func() {
		// See if there was a panic...
		fmt.Println(recover())
		exitMtx.Lock()
		println() // make it look nice after the ^C
		logger.Info("[glutton ] shutting down...")
		onErrorExit(processor.Shutdown())
	}

	defer exit()
	onInterruptSignal(func() {
		exit()
		os.Exit(0)
	})

	onErrorExit(processor.Start())
}
