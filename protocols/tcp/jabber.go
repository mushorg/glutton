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

// parse Jabber client
func parseJabberClient(conn net.Conn, md connection.Metadata, dataClient []byte, logger interfaces.Logger, h interfaces.Honeypot) error {
	v := JabberClient{STo: "none", Version: "none"}
	if err := xml.Unmarshal(dataClient, &v); err != nil {
		return err
	}

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	if err = h.ProduceTCP("jabber", conn, md, dataClient, v); err != nil {
		logger.Error("Failed to produce message", producer.ErrAttr(err), slog.String("handler", "jabber"))
	}

	logger.Info(
		fmt.Sprintf("STo : %v Version: %v XMLns: %v XMLName: %v", v.STo, v.Version, v.XMLns, v.XMLName),
		slog.String("handler", "jabber"),
		slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
		slog.String("src_ip", host),
		slog.String("src_port", port),
	)
	return nil
}

// read client msg
func readMsgJabber(conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	r := bufio.NewReader(conn)
	line, _, err := r.ReadLine()
	if err != nil {
		logger.Debug("Failed to read line", slog.String("handler", "jabber"), producer.ErrAttr(err))
		return nil
	}
	return parseJabberClient(conn, md, line[:1024], logger, h)
}

// HandleJabber main handler
func HandleJabber(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close connection", slog.String("handler", "jabber"), producer.ErrAttr(err))
		}
	}()

	v := &ServersJabber{Version: "1"}
	v.Svs = append(v.Svs, serverJabber{"Test_VPN", "127.0.0.1"})

	output, err := xml.MarshalIndent(v, "  ", "    ")
	if err != nil {
		return err
	}
	if _, err := conn.Write(output); err != nil {
		return err
	}
	if err := readMsgJabber(conn, md, logger, h); err != nil {
		return err
	}
	return nil
}
