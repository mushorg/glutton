package tcp

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
)

// ServersJabber defines servers structure
type ServersJabber struct {
	XMLName xml.Name       `xml:"servers"`
	Version string         `xml:"version,attr"`
	Svs     []serverJabber `xml:"server"`
}

// define server structure in Jabber protocol
type serverJabber struct {
	ServerName string `xml:"serverName"`
	ServerIP   string `xml:"serverIP"`
}

// JabberClient structure in Jabber protocol
type JabberClient struct {
	STo         string   `xml:"to,attr"`
	Version     string   `xml:"version,attr"`
	XMLns       string   `xml:"xmlns,attr"`
	ID          string   `xml:"id,attr"`
	XMLnsStream string   `xml:"xmlns stream,attr"`
	XMLName     xml.Name `xml:"http://etherx.jabber.org/streams stream"`
}

type parsedJabber struct {
	Direction string `json:"direction,omitempty"`
	Command   string `json:"command,omitempty"`
	Path      string `json:"path,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
}

// HandleJabber main handler
func HandleJabber(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	events := []parsedJabber{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("jabber", conn, md, helpers.FirstOrEmpty[parsedJabber](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", producer.ErrAttr(err), slog.String("handler", "jabber"))
		}
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close connection", slog.String("handler", "jabber"), producer.ErrAttr(err))
		}
	}()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("handler", "jabber"), producer.ErrAttr(err))
		endReason = connection.EndTimeout
		return nil
	}

	v := &ServersJabber{Version: "1"}
	v.Svs = append(v.Svs, serverJabber{"Test_VPN", "127.0.0.1"})

	output, err := xml.MarshalIndent(v, "  ", "    ")
	if err != nil {
		return err
	}
	if _, err := conn.Write(output); err != nil {
		endReason = connection.EndWriteError
		return err
	}
	events = append(events, parsedJabber{Direction: "write", Command: "servers", Payload: output})

	r := bufio.NewReader(conn)
	line, _, err := r.ReadLine()
	if err != nil {
		logger.Debug("Failed to read line", slog.String("handler", "jabber"), producer.ErrAttr(err))
		endReason = connection.EndReasonFromRead(err)
		return nil
	}
	if len(line) > 1024 {
		line = line[:1024]
	}
	client := JabberClient{STo: "none", Version: "none"}
	_ = xml.Unmarshal(line, &client)
	events = append(events, parsedJabber{
		Direction: "read",
		Command:   "stream",
		Path:      client.STo,
		Payload:   line,
	})

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err == nil {
		logger.Info(
			fmt.Sprintf("STo : %v Version: %v XMLns: %v XMLName: %v", client.STo, client.Version, client.XMLns, client.XMLName),
			slog.String("handler", "jabber"),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("src_ip", host),
			slog.String("src_port", port),
		)
	}
	return nil
}
