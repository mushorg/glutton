package glutton

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"net"
)

type ServersJabber struct {
	XMLName xml.Name       `xml:"servers"`
	Version string         `xml:"version,attr"`
	Svs     []serverJabber `xml:"server"`
}

type serverJabber struct {
	ServerName string `xml:"serverName"`
	ServerIP   string `xml:"serverIP"`
}

type JabberClient struct {
	STo         string   `xml:"to,attr"`
	Version     string   `xml:"version,attr"`
	XMLns       string   `xml:"xmlns,attr"`
	Id          string   `xml:"id,attr"`
	XMLnsStream string   `xml:"xmlns stream,attr"`
	XMLName     xml.Name `xml:"http://etherx.jabber.org/streams stream"`
}

// parse Jabber client
func parseJabberClient(dataClient string, g *Glutton) error {
	v := JabberClient{STo: "none", Version: "none"}
	err := xml.Unmarshal([]byte(dataClient), &v)
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
	for i := 1; true; i++ {
		line, _, err = r.ReadLine()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[jabber  ] error: %v", err))
			return err
		}
		dataClient := string(line[:1024])
		parseJabberClient(dataClient, g)

	}
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
	conn.Write(output)
	err = readMsgJabber(conn, g)
	if err != nil {
		g.logger.Error(fmt.Sprintf("[jabber  ] error: %v", err))
		return err
	}
	return nil
}
