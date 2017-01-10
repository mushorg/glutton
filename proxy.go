package glutton

import "net"

func tcpProxy(conn *net.TCPConn, remoteAddress string) error {
	rAddr, err := net.ResolveTCPAddr("tcp", remoteAddress)
	if err != nil {
		return err
	}

	rConn, err := net.DialTCP("tcp", nil, rAddr)
	if err != nil {
		return err
	}
	defer rConn.Close()

	// Request loop
	go func() {
		for {
			data := make([]byte, 1024*1024)
			n, err := conn.Read(data)
			if err != nil {
				break
			}
			rConn.Write(data[:n])
		}
	}()

	// Response loop
	for {
		data := make([]byte, 1024*1024)
		n, err := rConn.Read(data)
		if err != nil {
			break
		}
		conn.Write(data[:n])
	}
	return nil
}
