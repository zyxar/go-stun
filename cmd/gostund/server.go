package main

import (
	"net"
)

type Server struct {
	conn *net.UDPConn
}

func NewServer(addr string) (*Server, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	return &Server{conn: conn}, nil
}

func (this *Server) Close() error {
	return this.conn.Close()
}
