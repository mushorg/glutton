package glutton

import (
	"net"
	"net/url"
	"strings"
)

// mapProtocolHandler map protocol handlers to corresponding protocol
func (g *Glutton) mapProtocolHandler() {

	g.protocolHandlers["smtp"] = func(conn net.Conn) {
		g.HandleSMTP(conn)
	}
	g.protocolHandlers["rdp"] = func(conn net.Conn) {
		g.HandleRDP(conn)
	}
	g.protocolHandlers["smb"] = func(conn net.Conn) {
		g.HandleSMB(conn)
	}
	g.protocolHandlers["ftp"] = func(conn net.Conn) {
		g.HandleFTP(conn)
	}
	g.protocolHandlers["sip"] = func(conn net.Conn) {
		g.HandleSIP(conn)
	}
	g.protocolHandlers["rfb"] = func(conn net.Conn) {
		g.HandleRFB(conn)
	}
	g.protocolHandlers["telnet"] = func(conn net.Conn) {
		g.HandleTelnet(conn)
	}
	g.protocolHandlers["proxy_ssh"] = func(conn net.Conn) {
		destination := &url.URL{Scheme: "tcp", Host: "192.168.1.8:22"}
		g.NewSSHProxy(conn, destination.Host)
	}
	g.protocolHandlers["default"] = func(conn net.Conn) {
		snip, bufConn, err := g.Peek(conn, 4)
		g.OnErrorClose(err, conn)
		httpMap := map[string]bool{"GET ": true, "POST": true, "HEAD": true, "OPTI": true}
		if _, ok := httpMap[strings.ToUpper(string(snip))]; ok == true {
			g.HandleHTTP(bufConn)
		} else {
			g.HandleTCP(bufConn)
		}
	}
}
