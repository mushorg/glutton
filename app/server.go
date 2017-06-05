package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"

	"github.com/mushorg/glutton"
)

func onErrorExit(err error) {
	if err != nil {
		fmt.Println("[glutton ] %+v", err)
		os.Exit(0)
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

	gtn, err := glutton.New(iface, confPath, logPath, enableDebug)
	onErrorExit(err)

	err = gtn.Init()
	onErrorExit(err)

	exitMtx := sync.RWMutex{}
	exit := func() {
		// See if there was a panic...
		fmt.Fprintln(os.Stderr, recover())
		exitMtx.Lock()
		println() // make it look nice after the ^C
		fmt.Println("[glutton ] shutting down...")

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
