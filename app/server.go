package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/mushorg/glutton"
	"github.com/mushorg/glutton/config"
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

	iface := flag.String("interface", "eth0", "Interface to work with")
	logPath := flag.String("log-path", "/dev/null", "Log file path")
	confPath := flag.String("conf-path", "config/", "Config directory path")
	enableDebug := flag.Bool("debug", false, "Set to enable debug log")
	flag.Parse()

	// Setting up the logger
	logger := log.New()
	// Write log to file and stdout
	f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	onErrorExit(err)
	logger.Out = io.MultiWriter(f, os.Stdout)
	if *enableDebug == true {
		logger.Level = log.DebugLevel
	}
	logger.Formatter = &log.TextFormatter{ForceColors: true}

	// Loading the congiguration
	logger.Info("[glutton ] Loading configurations from: config/conf.yaml")
	conf := config.Init(*confPath, logger)

	gtn, err := glutton.New(*iface, conf, logger)
	onErrorExit(err)

	err = gtn.Init()
	onErrorExit(err)

	exitMtx := sync.RWMutex{}
	exit := func() {
		// See if there was a panic...
		fmt.Fprintln(os.Stderr, recover())
		exitMtx.Lock()
		println() // make it look nice after the ^C
		logger.Info("[glutton ] shutting down...")

		// TODO
		// Close connections on shutdown.
		onErrorExit(gtn.Shutdown())
	}
	defer exit()

	onInterruptSignal(func() {
		exit()
		os.Exit(0)
	})

	onErrorExit(gtn.Start())
}
