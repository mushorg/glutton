package main // import "github.com/mushorg/glutton"

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/mushorg/glutton"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func onErrorExit(err error) {
	if err != nil {
		fmt.Printf("[glutton ] %+v\n", err)
		os.Exit(0)
	}
}

func onInterruptSignal(fn func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

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

	pflag.StringP("interface", "i", "eth0", "Bind to this interface")
	pflag.StringP("logpath", "l", "/dev/null", "Log file path")
	pflag.StringP("confpath", "c", "config/", "Configuration file path")
	pflag.BoolP("debug", "d", false, "Enable debug mode")

	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	gtn, err := glutton.New()
	onErrorExit(err)

	err = gtn.Init()
	onErrorExit(err)

	exitMtx := sync.RWMutex{}
	exit := func() {
		// See if there was a panic...
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, recover())
		}
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
