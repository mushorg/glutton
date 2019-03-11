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
	if runtime.GOOS == "linux" {
		if isCommandAvailable("lsof") {
			out, err := exec.Command("/bin/sh", "-c", fmt.Sprintf("lsof -p %d", os.Getpid())).Output()
			if err != nil {
				log.Fatal(err)
			}
			lines := strings.Split(string(out), "\n")
			return len(lines) - 1
		}
		log.Fatalln("lsof command does not exist. Kindly run sudo apt install lsof")
	}
	log.Fatalln("this command is not available on non-linux based operating systems")
	return 0
}

func countRunningRoutines() int {
	return runtime.NumGoroutine()
}

func (g *Glutton) startMonitor(quit chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				openFiles := countOpenFiles()
				runningRoutines := countRunningRoutines()
				g.logger.Info(fmt.Sprintf(
					"[system  ] running Go routines: %d, open files: %d, open connections: %d",
					openFiles, runningRoutines, g.processor.Connections.Length(),
				))
			case <-quit:
				g.logger.Info("[system  ] Monitoring stopped..")
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
