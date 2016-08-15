package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/MohammadBilalArif/glutton"
	"github.com/hectane/go-nonblockingchan"
	"log"
	"os/exec"
	"regexp"
	"strconv"
)

const regexpression = `\[(\d+\.\d+)(?:\s+)?\]\s+\[\w+]\s+\w+\s+\w+\s\w+\s+.+?src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+sport=(\d+)\s+dport=(\d+)\s+`

const connBufferSize int = 30000000

func Monitor_Connections(proto string, channel *nbc.NonBlockingChan) {
	args := []string{
		"--buffer-size", strconv.Itoa(connBufferSize),
		"-E",
		"-o", "timestamp,extended,id",
		"-p", proto,
		"-e", "NEW",
	}
	cmd := exec.Command("conntrack", args...)
	stderrPipe, err := cmd.StderrPipe()
	glutton.CheckError(err)
	go func() {
		stderr := bufio.NewReader(stderrPipe)
		for {
			line, _, err := stderr.ReadLine()
			glutton.CheckError(err)
			log.Println(string(line))
		}
	}()
	stdoutPipe, err := cmd.StdoutPipe()
	glutton.CheckError(err)
	stdout := bufio.NewReader(stdoutPipe)
	fmt.Println(proto, "Starting conntrack...")
	cmd.Start()
	var buffer bytes.Buffer
	for {
		frag, isPrefix, err := stdout.ReadLine()
		glutton.CheckError(err)
		buffer.Write(frag)
		if !isPrefix {
			line := buffer.String()
			go func() {
				re := regexp.MustCompile(regexpression)
				str := re.FindStringSubmatch(line)
				channel.Send <- str
			}()
			buffer.Reset()
		}
	}
}
