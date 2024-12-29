package main // import "github.com/mushorg/glutton/app"

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
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
	fmt.Printf("%s %s\n\n", VERSION, BUILDDATE)

	pflag.StringP("interface", "i", "eth0", "Bind to this interface")
	pflag.IntP("ssh", "s", 0, "Override SSH port")
	pflag.StringP("logpath", "l", "/dev/null", "Log file path")
	pflag.StringP("confpath", "c", "config/", "Configuration file path")
	pflag.BoolP("debug", "d", false, "Enable debug mode")
	pflag.Bool("version", false, "Print version")
	pflag.String("var-dir", "/var/lib/glutton", "Set var-dir")

	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	if viper.IsSet("ssh") {
		viper.Set("ports.ssh", viper.GetInt("ssh"))
	}

	if viper.GetBool("version") {
		return
	}

	g, err := glutton.New(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	if err := g.Init(); err != nil {
		log.Fatal("Failed to initialize Glutton:", err)
	}

	exit := func() {
		// See if there was a panic...
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, r)
			fmt.Println("stacktrace from panic: \n" + string(debug.Stack()))
		}
		g.Shutdown()
	}

	// capture and handle signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Print("\r")
		exit()
		fmt.Println()
		os.Exit(0)
	}()

	if err := g.Start(); err != nil {
		exit()
		log.Fatal("Failed to start Glutton server:", err)
	}
}
