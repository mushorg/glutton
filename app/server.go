package main // import "github.com/mushorg/glutton/app"

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/mushorg/glutton"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	// VERSION is set by the makefile
	VERSION = "v0.0.0"
	// BUILDDATE is set by the makefile
	BUILDDATE = ""
)

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
	fmt.Printf("%s %s\n", VERSION, BUILDDATE)

	pflag.StringP("interface", "i", "eth0", "Bind to this interface")
	pflag.StringP("logpath", "l", "/dev/null", "Log file path")
	pflag.StringP("confpath", "c", "config/", "Configuration file path")
	pflag.BoolP("debug", "d", false, "Enable debug mode")
	pflag.Bool("version", false, "Print version")
	pflag.String("var-dir", "/var/lib/glutton", "Set var-dir")

	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	if viper.GetBool("version") {
		return
	}

	gtn, err := glutton.New()
	if err != nil {
		log.Fatal(err)
	}

	err = gtn.Init()
	if err != nil {
		log.Fatal(err)
	}

	exitMtx := sync.RWMutex{}
	exit := func() {
		// See if there was a panic...
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, recover())
		}
		exitMtx.Lock()
		println() // make it look nice after the ^C
		fmt.Println("shutting down...")
		err = gtn.Shutdown()
		if err != nil {
			log.Fatal(err)
		}
	}
	defer exit()

	onInterruptSignal(func() {
		exit()
		os.Exit(0)
	})

	err = gtn.Start()
	if err != nil {
		log.Fatal(err)
	}
}
