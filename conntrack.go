package glutton

import (
	"bufio"
	"bytes"
	. "fmt"
	"github.com/hectane/go-nonblockingchan"
	"log"
	"os/exec"
	"regexp"
)

const tcpRegExp = `\[\w+]\s+\w+\s+.+?src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+sport=(\d+)\s+dport=(\d+)\s+`
const udpRegExp = `\[(\w+)]\s+\w+\s+.+?src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+sport=(\d+)\s+dport=(\d+)\s+`

func MonitorTCPConnections(channel *nbc.NonBlockingChan) {
	args := []string{
		"--buffer-size", "30000000",
		"-E",
		"-p", "tcp",
		"-e", "NEW",
	}
	cmd := exec.Command("conntrack", args...)
	stderrPipe, err := cmd.StderrPipe()
	CheckError(err)
	go func() {
		stderr := bufio.NewReader(stderrPipe)
		for {
			line, _, err := stderr.ReadLine()
			CheckError(err)
			log.Println(string(line))
		}
	}()
	stdoutPipe, err := cmd.StdoutPipe()
	CheckError(err)
	stdout := bufio.NewReader(stdoutPipe)
	Println("[TCP] Starting conntrack...")
	cmd.Start()
	var buffer bytes.Buffer
	for {
		frag, isPrefix, err := stdout.ReadLine()
		CheckError(err)
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

func MonitorUDPConnections(channel *nbc.NonBlockingChan) {
	args := []string{
		"--buffer-size", "30000000",
		"-E",
		"-p", "udp",
		"-e", "ALL",
	}
	cmd := exec.Command("conntrack", args...)
	stderrPipe, err := cmd.StderrPipe()
	CheckError(err)
	go func() {
		stderr := bufio.NewReader(stderrPipe)
		for {
			line, _, err := stderr.ReadLine()
			CheckError(err)
			log.Println(string(line))
		}
	}()
	stdoutPipe, err := cmd.StdoutPipe()
	CheckError(err)
	stdout := bufio.NewReader(stdoutPipe)
	Println("[UDP] Starting conntrack...")
	cmd.Start()
	var buffer bytes.Buffer
	for {
		frag, isPrefix, err := stdout.ReadLine()
		CheckError(err)
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
