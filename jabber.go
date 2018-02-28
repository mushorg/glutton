package glutton

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"net"
)

//define servers structure
type ServersJabber struct {
	XMLName xml.Name       `xml:"servers"`
	Version string         `xml:"version,attr"`
	Svs     []serverJabber `xml:"server"`
}

//define server structure in Jabber protocol
type serverJabber struct {
	ServerName string `xml:"serverName"`
	ServerIP   string `xml:"serverIP"`
}

//Client structure in Jabber protocol
type JabberClient struct {
	STo         string   `xml:"to,attr"`
	Version     string   `xml:"version,attr"`
	XMLns       string   `xml:"xmlns,attr"`
	Id          string   `xml:"id,attr"`
	XMLnsStream string   `xml:"xmlns stream,attr"`
	XMLName     xml.Name `xml:"http://etherx.jabber.org/streams stream"`
}

// parse Jabber client
func parseJabberClient(dataClient []byte, g *Glutton) error {
	v := JabberClient{STo: "none", Version: "none"}
	err := xml.Unmarshal(dataClient, &v)
	if err != nil {
		g.logger.Error(fmt.Sprintf("[jabber  ] err: %v", err))
		return err
	}
	g.logger.Info(fmt.Sprintf("[jabber  ] STo : %v Version: %v XMLns: %v XMLName: %v", v.STo, v.Version, v.XMLns, v.XMLName))
	return nil
}

// read client msg
func readMsgJabber(conn net.Conn, g *Glutton) (err error) {
	var line []byte
	r := bufio.NewReader(conn)
	line, _, err = r.ReadLine()
	if err != nil {
		g.logger.Error(fmt.Sprintf("[jabber  ] error: %v", err))
		return err
	}
	parseJabberClient(line[:1024], g)
	return nil
}

// HandleJabber
func (g *Glutton) HandleJabber(ctx context.Context, conn net.Conn) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[jabber  ]  error: %v", err))
		}
	}()

	v := &ServersJabber{Version: "1"}
	v.Svs = append(v.Svs, serverJabber{"Test_VPN", "127.0.0.1"})

	output, err := xml.MarshalIndent(v, "  ", "    ")
	if err != nil {
		g.logger.Error(fmt.Sprintf("[jabber  ]  error: %v", err))
		return err
	}
	if _, err := conn.Write(output); err != nil {
		g.logger.Error(fmt.Sprintf("[jabber  ]  error: %v", err))
		return err
	}
	if err := readMsgJabber(conn, g); err != nil {
		g.logger.Error(fmt.Sprintf("[jabber  ] error: %v", err))
		return err
	}
	return nil
}
