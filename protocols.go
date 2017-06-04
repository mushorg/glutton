package glutton

import (
	"net"
	"strings"
)

// mapProtocolHandlers map protocol handlers to corresponding protocol
func (g *Glutton) mapProtocolHandlers() {

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
        g.protocolHandlers["jabber"] = func(conn net.Conn) {
                g.HandleJabber(conn)
        }
	g.protocolHandlers["proxy_ssh"] = func(conn net.Conn) {
		g.sshProxy.handle(conn)
	}
	g.protocolHandlers["default"] = func(conn net.Conn) {
		snip, bufConn, err := g.Peek(conn, 4)
		g.onErrorClose(err, conn)
		httpMap := map[string]bool{"GET ": true, "POST": true, "HEAD": true, "OPTI": true}
		if _, ok := httpMap[strings.ToUpper(string(snip))]; ok == true {
			g.HandleHTTP(bufConn)
		} else {
			g.HandleTCP(bufConn)
		}
	}
}
