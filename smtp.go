package glutton

import (
	"bufio"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"time"
)

// Client is a connection container
type Client struct {
	conn   net.Conn
	bufin  *bufio.Reader
	bufout *bufio.Writer
}

func (c *Client) w(s string) {
	c.bufout.WriteString(s + "\r\n")
	c.bufout.Flush()
}
func (c *Client) r(g *Glutton) string {
	reply, err := c.bufin.ReadString('\n')
	if err != nil {
		g.logger.Errorf("[smpt    ] %v", err)
	}
	return reply
}

func rwait() {
	// makes the process sleep for random time
	rand.Seed(time.Now().Unix())
	// between 0.5 - 1.5 seconds
	rtime := rand.Intn(1500) + 500
	duration := time.Duration(rtime) * time.Millisecond
	time.Sleep(duration)
}
func validateMail(query string) bool {
	email := regexp.MustCompile("^MAIL FROM:<.+@.+>$") // naive regex
	if email.MatchString(query) {
		return true
	}
	return false
}
func validateRCPT(query string) bool {
	rcpt := regexp.MustCompile("^RCPT TO:<.+@.+>$")
	if rcpt.MatchString(query) {
		return true
	}
	return false
}

// HandleSMTP takes a net.Conn and does basic SMTP communication
func (g *Glutton) HandleSMTP(conn net.Conn) {
	defer conn.Close()
	client := &Client{
		conn:   conn,
		bufin:  bufio.NewReader(conn),
		bufout: bufio.NewWriter(conn),
	}
	rwait()
	client.w("220 Welcome!")
	for {
		query := strings.Trim(client.r(g), "\r\n")
		g.logger.Infof("[smtp    ] Payload : %q", query)
		if strings.HasPrefix(query, "HELO ") {
			rwait()
			client.w("250 Hello! Pleased to meet you.")
		} else if validateMail(query) {
			rwait()
			client.w("250 OK")
		} else if validateRCPT(query) {
			rwait()
			client.w("250 OK")
		} else if strings.Compare(query, "DATA") == 0 {
			client.w("354 End data with <CRLF>.<CRLF>")
			for strings.Compare(client.r(g), ".\r\n") != 0 {
			}
			rwait()
			client.w("250 OK")
		} else if strings.Compare(query, "QUIT") == 0 {
			client.w("Bye")
			break
		} else {
			client.w("Recheck the command you entered.")
		}
	}
}
