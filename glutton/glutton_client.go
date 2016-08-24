package main

import (
	"net"
)

func TCPClient(addr string) *net.TCPConn {

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		println("ResolveTCPAddr failed:", err.Error())
		return nil
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		println("Dial failed: Target Service either not active or not responding ", err.Error())
		return nil
	}

	return conn
}

func UDPClient(addr string) *UDPConn {
	udpAddr, err := net.ResolveUDPAddr("up4", service)
	if err != nil {
		println("ResolveUDPAddr failed:", err.Error())
		return nil
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		println("Dial failed: Target Service either not active or not responding ", err.Error())
		return nil
	}
	return conn

}
