package glutton

import (
	"bufio"
	"fmt"
	"net"

	log "github.com/Sirupsen/logrus"
)

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
		fmt.Println("e ", err)
	}
	return reply
}

func HandleSMTP(conn net.Conn) {
	defer conn.Close()
	client := &Client{
		conn:   conn,
		bufin:  bufio.NewReader(conn),
		bufout: bufio.NewWriter(conn),
	}
	client.w("220 Welcome")
	log.Infof("[smpt] Payload %q", client.r())
}
