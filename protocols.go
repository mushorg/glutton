package glutton

import (
	"net"
	"strings"
)

// mapProtocolHandlers map protocol handlers to corresponding protocol
func (g *Glutton) mapProtocolHandlers() {

	g.protocolHandlers["smtp"] = func(conn net.Conn) error {
		return g.HandleSMTP(conn)
	}
	g.protocolHandlers["rdp"] = func(conn net.Conn) error {
		return g.HandleRDP(conn)
	}
	g.protocolHandlers["smb"] = func(conn net.Conn) error {
		return g.HandleSMB(conn)
	}
	g.protocolHandlers["ftp"] = func(conn net.Conn) error {
		return g.HandleFTP(conn)
	}
	g.protocolHandlers["sip"] = func(conn net.Conn) error {
		return g.HandleSIP(conn)
	}
	g.protocolHandlers["rfb"] = func(conn net.Conn) error {
		return g.HandleRFB(conn)
	}
	g.protocolHandlers["telnet"] = func(conn net.Conn) error {
		return g.HandleTelnet(conn)
	}
	g.protocolHandlers["proxy_ssh"] = func(conn net.Conn) error {
		return g.sshProxy.handle(conn)
	}
	g.protocolHandlers["default"] = func(conn net.Conn) error {
		snip, bufConn, err := g.Peek(conn, 4)
		g.onErrorClose(err, conn)
		httpMap := map[string]bool{"GET ": true, "POST": true, "HEAD": true, "OPTI": true}
		if _, ok := httpMap[strings.ToUpper(string(snip))]; ok == true {
			return g.HandleHTTP(bufConn)
		} else {
			return g.HandleTCP(bufConn)
		}
	}
}
