package glutton

import (
	"fmt"
	"net"
	"context"
	"encoding/xml"
	"bufio"
	"encoding/hex"
	"reflect"
	"unsafe"
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

type JabberClient struct {
		STo         string   `xml:"to,attr"`
	    Version     string   `xml:"version,attr"`
	    Xmlns       string   `xml:"xmlns,attr"`
	    Id          string   `xml:"id,attr"`
	    XmlnsStream string   `xml:"xmlns stream,attr"`
	    XMLName     xml.Name `xml:"http://etherx.jabber.org/streams stream"`
	}


func bytesToString(b []byte) string {
    bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
    sh := reflect.StringHeader{bh.Data, bh.Len}
    return *(*string)(unsafe.Pointer(&sh))
}

// parse Jabber client
func parseJabberClient( dataClient string , g *Glutton) string  {
	
	v := JabberClient{STo: "none", Version: "none"}

	err := xml.Unmarshal([]byte(dataClient), &v)
	if err != nil {
		g.logger.Error(fmt.Sprintf("[Jabber  *********   ] err: %v", err))
	}
	
	g.logger.Info(fmt.Sprintf("[Jabber  *********   ] STo: %v", v.STo))
	g.logger.Info(fmt.Sprintf("[Jabber  *********   ] Version: %v", v.Version))
	g.logger.Info(fmt.Sprintf("[Jabber  *********   ] Xmlns: %v", v.Xmlns))
	g.logger.Info(fmt.Sprintf("[Jabber  *********   ] XMLName: %v", v.XMLName))
	return v.STo

}

// read client msg
func readMsgJabber(conn net.Conn, g *Glutton) (msg string, err error) {
	var (isPrefix bool = true
         line []byte
      )

	r := bufio.NewReader(conn)
	for i := 1; true; i++ {
		line, isPrefix, err = r.ReadLine()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[Jabber     ] errJ: %v", err))
			break
			return
		}
		
		g.logger.Info(fmt.Sprintf("[Jabber     ] isPrefix: %v", isPrefix))
		g.logger.Info(fmt.Sprintf("[Jabber     ] line: %v", line))
		g.logger.Info(fmt.Sprintf("[Jabber     ] BytesToString: %v", bytesToString(line)))
		g.logger.Info(fmt.Sprintf("[Jabber     ] type line[0]: %T", reflect.TypeOf(line[0]) ))		
		g.logger.Info(fmt.Sprintf("[Jabber     ] \n%s", hex.Dump(line[0:])))
		dataClient := bytesToString(line)
		parseJabberClient(dataClient, g)

	}

	g.logger.Info(fmt.Sprintf("[Jabber     ] recv: %q", msg))
	return msg, err
}


// HandleJabber
func (g *Glutton) HandleJabber(ctx context.Context, conn net.Conn) (err error) {
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

    msg, err := readMsgJabber(conn, g)
    if err != nil {
		g.logger.Error(fmt.Sprintf("[Jaber......  ] error: %v", err))
	}
	g.logger.Info(fmt.Sprintf("[>>>>>>>>>>>>>>jabber<<<<<<<<<<<<<     ]  msg: %v", msg))
    g.logger.Info(fmt.Sprintf("------ write XML Server ---------"))
    return nil    

}
