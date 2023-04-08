package main // import "github.com/mushorg/glutton/app"

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
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

	ctx := context.Background()

	if err := gtn.Init(ctx); err != nil {
		log.Fatal(err)
	}

	exitMtx := sync.RWMutex{}
	exit := func() {
		// See if there was a panic...
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, r)
			fmt.Println("stacktrace from panic: \n" + string(debug.Stack()))
		}
		exitMtx.Lock()
		fmt.Println("\nshutting down...")
		if err := gtn.Shutdown(); err != nil {
			log.Fatal(err)
		}
	}
	defer exit()

	// capture and handle signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		exit()
		os.Exit(0)
	}()

	if err := gtn.Start(); err != nil {
		log.Fatalf("server start error: %s", err)
	}
}
