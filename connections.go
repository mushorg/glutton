package glutton

import (
	"log"
	"sync"
)

// ConnCounter keeps track of connections in Glutton
type ConnCounter interface {
	incrCon()
	decrCon()
	connectionsState()
	connectionClosed(string, string, string, error)
	reqAccepted()
	reqDropped()
}

// Connections will track the number of open connections and how many dropped by glutton,
// how many dropped by client.
type Connections struct {
	mutex sync.Mutex

	// TCP connections
	openedConnections int
	closedByGlutton   int
	closedByClient    int

	// UDP connections
	udpReqAccepted int // Number of Requests served by glutton
	udpReqDropped  int // Number of Requests dropped by glutton
}

func (c *Connections) incrCon() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.openedConnections++
}

func (c *Connections) decrCon() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.openedConnections--
}

func (c *Connections) reqAccepted() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.udpReqAccepted++
}

func (c *Connections) reqDropped() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.udpReqDropped++
}

func (c *Connections) connectionsState() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	log.Printf(`
		TCP: Open Connections:  %d
		TCP: Closed by Glutton: %d
		TCP: Closed by Clients: %d
		UDP: Accepted Requests: %d
		UDP: Dropped  Requests: %d
		`, c.openedConnections, c.closedByGlutton, c.closedByClient, c.udpReqAccepted, c.udpReqDropped)
}

// For now connectionClosed supports only proxy handler
func (c *Connections) connectionClosed(srcAddr, dstAddr, str string, err error) {
	c.mutex.Lock()
	c.openedConnections--
	if str == "Glutton" {
		c.closedByGlutton++
	} else {
		c.closedByClient++
	}
	c.mutex.Unlock()

	if err != nil && err.Error() == "EOF" {
		log.Printf("[TCP] Connection Closed by %s [%s -> %s] \n", str, srcAddr, dstAddr)
	} else {
		log.Printf("[TCP] Connection timeout [%s -> %s] \n", srcAddr, dstAddr)
	}
}
