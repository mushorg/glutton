package glutton

import (
	"net"

)

// HandleJabber
func (g *Glutton) HandleJabber(conn net.Conn) {
        g.logger.Infof("************Jabber**********************************")
        defer conn.Close()
}
