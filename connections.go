package glutton

import (
	"log"
	"sync"
)

type ConnCounter interface {
	addConnection()
	subConnection()
	connectionsState()
	connectionClosed(string, string, string, error)
}

// Connections will track the number of open connections and how many dropped by glutton,
// how many dropped by client.
type Connections struct {
	mutex sync.Mutex

	// TCP connections
	openedConnections int
	clossedByGlutton  int
	clossedByClient   int

	// UDP connections
	udpRequests   int // Number of Requests served by glutton
	udpReqDropped int // Number of Requests dropped by glutton
}

func (c *Connections) addConnection() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.openedConnections++
}

func (c *Connections) subConnection() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.openedConnections--
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
		`, c.openedConnections, c.clossedByGlutton, c.clossedByClient, c.udpRequests, c.udpReqDropped)
}

// For now connectionClosed supports only proxy handler
func (c *Connections) connectionClosed(srcAddr, dstAddr, str string, err error) {
	c.mutex.Lock()
	c.openedConnections--
	if str == "Glutton" {
		c.clossedByGlutton++
	} else {
		c.clossedByClient++
	}
	c.mutex.Unlock()

	if err != nil && err.Error() == "EOF" {
		log.Printf("[TCP] Connection Closed by %s [%s -> %s] \n", str, srcAddr, dstAddr)
	} else {
		log.Printf("[TCP] Connection timeout [%s -> %s] \n", srcAddr, dstAddr)
	}
}
