package glutton

import (
	"bufio"
	"bytes"
	"log"
	"os/exec"
	"regexp"
	"sync"

	"github.com/hectane/go-nonblockingchan"
)

const tcpRegExp = `\[\w+]\s+\w+\s+.+?src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+sport=(\d+)\s+dport=(\d+)\s+`
const udpRegExp = `\[(\w+)]\s+\w+\s+.+?src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+sport=(\d+)\s+dport=(\d+)\s+`

// MonitorTCPConnections monitors conntrack for TCP connections
func MonitorTCPConnections(channel *nbc.NonBlockingChan, wg *sync.WaitGroup) {
	defer wg.Done()

	args := []string{
		"--buffer-size", "30000000",
		"-E",
		"-p", "tcp",
		"-e", "NEW",
	}
	cmd := exec.Command("conntrack", args...)
	stderrPipe, err := cmd.StderrPipe()
	CheckError("", err)
	go func() {
		stderr := bufio.NewReader(stderrPipe)
		for {
			line, _, readErr := stderr.ReadLine()
			log.Println(string(line))
			CheckError("", readErr)
		}
	}()
	stdoutPipe, err := cmd.StdoutPipe()
	CheckError("", err)
	stdout := bufio.NewReader(stdoutPipe)
	cmd.Start()
	var buffer bytes.Buffer
	for {
		frag, isPrefix, err := stdout.ReadLine()
		CheckError("", err)
		buffer.Write(frag)
		if !isPrefix {
			line := buffer.String()
			go func() {
				re := regexp.MustCompile(tcpRegExp)
				str := re.FindStringSubmatch(line)
				channel.Send <- str

			}()
			buffer.Reset()
		}
	}
}

// MonitorUDPConnections monitors conntrack for UDP connections
func MonitorUDPConnections(channel *nbc.NonBlockingChan, wg *sync.WaitGroup) {
	defer wg.Done()

	args := []string{
		"--buffer-size", "30000000",
		"-E",
		"-p", "udp",
		"-e", "NEW",
	}
	cmd := exec.Command("conntrack", args...)
	stderrPipe, err := cmd.StderrPipe()
	CheckError("", err)
	go func() {
		stderr := bufio.NewReader(stderrPipe)
		for {
			line, _, readErr := stderr.ReadLine()
			log.Println(string(line))
			CheckError("", readErr)
		}
	}()
	stdoutPipe, err := cmd.StdoutPipe()
	CheckError("", err)
	stdout := bufio.NewReader(stdoutPipe)
	cmd.Start()
	var buffer bytes.Buffer
	for {
		frag, isPrefix, err := stdout.ReadLine()
		CheckError("", err)
		buffer.Write(frag)
		if !isPrefix {
			line := buffer.String()
			go func() {
				re := regexp.MustCompile(udpRegExp)
				str := re.FindStringSubmatch(line)
				channel.Send <- str

			}()
			buffer.Reset()
		}
	}
}
