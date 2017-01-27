package glutton

import (
	"bufio"
	"net"
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
		g.Logger.Errorf("[smpt    ] %v", err)
	}
	return reply
}

// HandleSMTP takes a net.Conn and does basic SMTP communication
func (g *Glutton) HandleSMTP(conn net.Conn) {
	defer conn.Close()
	client := &Client{
		conn:   conn,
		bufin:  bufio.NewReader(conn),
		bufout: bufio.NewWriter(conn),
	}
	client.w("220 Welcome")
	g.Logger.Infof("[smpt    ] Payload 1: %q", client.r(g))
	client.w("250 Is it me?")
	g.Logger.Infof("[smpt    ] Payload 2: %q", client.r(g))
	client.w("250 Sender")
	g.Logger.Infof("[smpt    ] Payload 3: %q", client.r(g))
	client.w("250 Recipient")
	g.Logger.Infof("[smpt    ] Payload 4: %q", client.r(g))
	client.w("354 Ok Send data ending with <CRLF>.<CRLF>")
	g.Logger.Infof("[smpt    ] Payload 5: %q", client.r(g))
}
