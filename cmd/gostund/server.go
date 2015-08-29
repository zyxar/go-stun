package main

import (
	"errors"
	"log"
	"net"

	"github.com/zyxar/go-stun"
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

func (this *Server) ProcessMessage(msg *stun.Message, dest *net.UDPAddr) error {
	switch msg.Type().Value() {
	case stun.TYPE_BINDING_REQUEST:
	// case stun.TYPE_SHARED_SECRET_REQUEST:
	default:
		return unsupportedError
	}
	// msg validation: fingerprint, integrity
	var _id [12]byte
	copy(_id[:], msg.Id())
	resp, _ := stun.CreateEmptyMessage(stun.TYPE_BINDING_RESPONSE, 0, _id)
	var laddr = this.conn.LocalAddr().(*net.UDPAddr)
	// mapped address
	var attr stun.Attribute = stun.CreateAddressAttribute(stun.ATTRIBUTE_MAPPED_ADDRESS, dest)
	resp.AddAttribute(attr)
	// xor-mapped address
	attr = stun.CreateAddressAttribute(stun.ATTRIBUTE_XOR_MAPPED_ADDRESS, dest)
	resp.AddAttribute(attr)
	// source address
	attr = stun.CreateAddressAttribute(stun.ATTRIBUTE_SOURCE_ADDRESS, laddr)
	resp.AddAttribute(attr)
	// changed address
	// server name
	resp.AddSoftwareAttribute("go.stund.server")
	// finalize
	log.Printf("Send:\n%s\n", resp.String())
	_, err := this.conn.WriteToUDP(resp.Encode(), dest)
	return err
}

var unsupportedError = errors.New("Unknown or unsupported request")
