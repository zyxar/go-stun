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
		if message, err := stun.NewMessage(b[:n]); err != nil {
			log.Println(err)
		} else {
			log.Println(message.Type().String(), message.Length(), message.Id())
			if err = response(nil, raddr, message); err != nil {
				log.Println(err)
			}
		}
	}
	server.Close()
}

func response(laddr, raddr *net.UDPAddr, message *stun.Message) error {
	conn, err := net.DialUDP(raddr.Network(), laddr, raddr)
	if err != nil {
		return err
	}
	payload := message.Encode()
	_, err = conn.Write(payload)
	conn.Close()
	return err
}
