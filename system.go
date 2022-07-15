package glutton

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
)

func countOpenFiles() (int, error) {
	if runtime.GOOS == "linux" {
		if isCommandAvailable("lsof") {
			out, err := exec.Command("/bin/sh", "-c", fmt.Sprintf("lsof -p %d", os.Getpid())).Output()
			if err != nil {
				log.Fatal(err)
			}
			lines := strings.Split(string(out), "\n")
			return len(lines) - 1, nil
		}
		return 0, errors.New("lsof command does not exist. Kindly run sudo apt install lsof")
	}
	return 0, errors.New("operating system type not supported for this command")
}

func (g *Glutton) startMonitor(quit chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				openFiles, err := countOpenFiles()
				if err != nil {
					fmt.Printf("Failed :%s", err)
				}
				runningRoutines := runtime.NumGoroutine()
				g.Logger.Info(fmt.Sprintf("running Go routines: %d, open files: %d", openFiles, runningRoutines))
			case <-quit:
				g.Logger.Info("monitoring stopped...")
				ticker.Stop()
				return
			}
		}
	}()
}

func isCommandAvailable(name string) bool {
	cmd := exec.Command("/bin/sh", "-c", "command -v "+name)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func getNonLoopbackIPs(ifaceName string) ([]net.IP, error) {
	nonLoopback := []net.IP{}

	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nonLoopback, err
	}

	for _, iface := range ifs {
		if strings.EqualFold(iface.Name, ifaceName) {
			for _, addr := range iface.Addresses {
				if !addr.IP.IsLoopback() && addr.IP.To4() != nil {
					nonLoopback = append(nonLoopback, addr.IP)
				}
			}
		}
	}

	if len(nonLoopback) == 0 {
		return nonLoopback, fmt.Errorf("unable to find any non-loopback addresses for: %s", ifaceName)
	}

	return nonLoopback, nil
}
