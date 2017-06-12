package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"

	"github.com/docopt/docopt-go"
	"github.com/mushorg/glutton"
)

var usage = `
Usage:
    server -i <interface> [options] 
    server -h | --help
Options:
    -i --interface=<iface>  Bind to this interface [default: eth0]. 
    -l --logpath=<path>     Log file path [default: /dev/null].
    -c --confpath=<path>    Configuration file path [default: config/].
    -d --debug              Enable debug mode [default: false].
    -h --help               Show this screen.
`

func onErrorExit(err error) {
	if err != nil {
		fmt.Printf("[glutton ] %+v\n", err)
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

	args, err := docopt.Parse(usage, os.Args[1:], true, "", true)
	onErrorExit(err)

	gtn, err := glutton.New(args)
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
		onErrorExit(gtn.Shutdown())
	}
	defer exit()

	onInterruptSignal(func() {
		exit()
		os.Exit(0)
	})

	onErrorExit(gtn.Start())
}
