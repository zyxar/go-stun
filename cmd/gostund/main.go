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
			continue
		}
		go func() {
			if message, err := stun.NewMessage(b[:n]); err != nil {
				log.Println(err)
			} else {
				log.Printf("%s %s/[% x]", message.Type().String(), message.Vendor(), message.Id())
				if err = response(server.conn, raddr, message); err != nil {
					log.Println(err)
				}
			}
		}()
	}
	server.Close()
}

func response(conn *net.UDPConn, raddr *net.UDPAddr, message *stun.Message) (err error) {
	payload := message.Encode()
	_, err = conn.WriteToUDP(payload, raddr)
	return
}
