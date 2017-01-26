package glutton

import (
	"bufio"
	"net"

	log "github.com/Sirupsen/logrus"
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
func (c *Client) r() string {
	reply, err := c.bufin.ReadString('\n')
	if err != nil {
		log.Errorf("[smpt    ] %v", err)
	}
	return reply
}

// HandleSMTP takes a net.Conn and does basic SMTP communication
func HandleSMTP(conn net.Conn) {
	defer conn.Close()
	client := &Client{
		conn:   conn,
		bufin:  bufio.NewReader(conn),
		bufout: bufio.NewWriter(conn),
	}
	client.w("220 Welcome")
	log.Infof("[smpt    ] Payload 1: %q", client.r())
	client.w("250 Is it me?")
	log.Infof("[smpt    ] Payload 2: %q", client.r())
	client.w("250 Sender")
	log.Infof("[smpt    ] Payload 3: %q", client.r())
	client.w("250 Recipient")
	log.Infof("[smpt    ] Payload 4: %q", client.r())
	client.w("354 Ok Send data ending with <CRLF>.<CRLF>")
	log.Infof("[smpt    ] Payload 5: %q", client.r())
}
