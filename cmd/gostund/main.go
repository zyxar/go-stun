package main

import (
	"log"
	"net"

	"github.com/zyxar/go-stun"
)

func main() {
	server, err := NewServer(":3478")
	if err != nil {
		panic(err)
	}
	b := make([]byte, 2048)
	for {
		n, raddr, err := server.conn.ReadFromUDP(b)
		if err != nil {
			log.Println(err)
		}
		if packet, err := stun.NewPacket(b[:n]); err != nil {
			log.Println(err)
		} else {
			if err = response(nil, raddr, packet); err != nil {
				log.Println(err)
			}
		}
	}
	server.Close()
}

func response(laddr, raddr *net.UDPAddr, packet *stun.Packet) error {
	conn, err := net.DialUDP(raddr.Network(), laddr, raddr)
	if err != nil {
		return err
	}
	payload := packet.Encode()
	_, err = conn.Write(payload)
	conn.Close()
	return err
}
