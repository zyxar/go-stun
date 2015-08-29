package main

import (
	"log"

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
				log.Printf("Recv:\n%s\n", message.String())
				if err = server.ProcessMessage(message, raddr); err != nil {
					log.Println(err)
				}
			}
		}()
	}
	server.Close()
}
