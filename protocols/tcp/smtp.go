package tcp

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/mushorg/glutton/protocols/interfaces"
	"go.uber.org/zap"
)

// maximum lines that can be read after the "DATA" command
const maxDataRead = 500

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
func (c *Client) read() (string, error) {
	return c.bufin.ReadString('\n')
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
	return email.MatchString(query)
}
func validateRCPT(query string) bool {
	rcpt := regexp.MustCompile("^RCPT TO:<.+@.+>$")
	return rcpt.MatchString(query)
}

// HandleSMTP takes a net.Conn and does basic SMTP communication
func HandleSMTP(ctx context.Context, conn net.Conn, logger interfaces.Logger, h interfaces.Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error(fmt.Sprintf("[smtp    ]  error: %v", err))
		}
	}()

	md, err := h.MetadataByConnection(conn)
	if err != nil {
		return err
	}

	client := &Client{
		conn:   conn,
		bufin:  bufio.NewReader(conn),
		bufout: bufio.NewWriter(conn),
	}
	rwait()
	client.w("220 Welcome!")

	for {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			return err
		}
		data, err := client.read()
		if err != nil {
			break
		}
		query := strings.Trim(data, "\r\n")
		logger.Info(fmt.Sprintf("[smtp    ] Payload : %q", query))
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
			for readctr := maxDataRead; readctr >= 0; readctr-- {
				data, err = client.read()
				if err != nil {
					break
				}
				if err := h.ProduceTCP("smtp", conn, md, []byte(data), struct {
					Message string `json:"message,omitempty"`
				}{Message: query}); err != nil {
					logger.Error("failed to produce message", zap.String("protocol", "smpt"), zap.Error(err))
				}
				logger.Info(fmt.Sprintf("[smtp    ] Data : %q", data))
				// exit condition
				if strings.Compare(data, ".\r\n") == 0 {
					break
				}
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
	return nil
}
