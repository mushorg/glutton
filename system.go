package glutton

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func countOpenFiles() int {
	out, err := exec.Command("/bin/sh", "-c", fmt.Sprintf("lsof -p %v", os.Getpid())).Output()
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(out), "\n")
	return len(lines) - 1
}

func countRunningRoutines() int {
	return runtime.NumGoroutine()
}

func (g *Glutton) startMonitor() {
	ticker := time.NewTicker(10 * time.Second)
	// TODO: return channel and stop monitor on shutdown
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				openFiles := countOpenFiles()
				runningRoutines := countRunningRoutines()
				g.logger.Infof("[system  ] Running Go routines: %d and open files: %d", openFiles, runningRoutines)
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
}
