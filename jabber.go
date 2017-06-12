package glutton

import (
	"fmt"
	"net"
	"encoding/xml"
)

type ServersJabber struct {
    XMLName xml.Name `xml:"servers"`
    Version string   `xml:"version,attr"`
    Svs     []serverJabber `xml:"server"`
}

type serverJabber struct {
    ServerName string `xml:"serverName"`
    ServerIP   string `xml:"serverIP"`
}

// HandleJabber
func (g *Glutton) HandleJabber(conn net.Conn) (err error) {
	g.logger.Info(fmt.Sprintf("---------------[Jabber  ] send:"))
	defer func() {
		err = conn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[>>>>>>>>>>>>>>jabber<<<<<<<<<<<<<     ]  error: %v", err))
		}
	}()


	v := &ServersJabber{Version: "1"}
    v.Svs = append(v.Svs, serverJabber{"Test_VPN", "127.0.0.1"})
 
    output, err := xml.MarshalIndent(v, "  ", "    ")
    if err != nil {
        g.logger.Error(fmt.Sprintf("[>>>>>>>>>>>>>>jabber<<<<<<<<<<<<<     ]  error: %v", err))
    }
 
    conn.Write(output)
    g.logger.Info(fmt.Sprintf("------ write XML Server ---------"))
    return nil    

}
