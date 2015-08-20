package stun

import (
	"bytes"
	"testing"
)

func TestPacketCreation(t *testing.T) {
	head := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12}
	packet, err := makePacket(TYPE_BINDING_REQUEST, 0, head[4:])
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare(packet.Bytes(), head) != 0 {
		t.Error("makePacket failed")
	}
	packet2, err := MakePacket(head)
	if bytes.Compare(packet2.Bytes(), head) != 0 {
		t.Error("MakePacket failed")
	}
}

func TestPacketBytes(t *testing.T) {
	head := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12}
	pkt := Packet{
		_type:  TYPE_BINDING_REQUEST,
		length: 0,
		cookie: MAGIC_COOKIE,
	}
	copy(pkt.id[:], head[8:])
	if bytes.Compare(head, pkt.Bytes()) != 0 {
		t.Error("packet ->Bytes failed")
	}
}

func TestPacketAddAttr(t *testing.T) {
	head := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12}
	pkt := Packet{
		_type:  TYPE_BINDING_REQUEST,
		length: 0,
		cookie: MAGIC_COOKIE,
	}
	copy(pkt.id[:], head[8:])
	if pkt.NAttributes() != 0 {
		t.Errorf("NAttributes incorrect: %d\n", pkt.NAttributes())
	}

	attribute, err := MakeSoftwareAttribute(&pkt, "TEST ROUTINE")
	if err != nil {
		t.Error(err)
	}
	pkt.AddAttribute(attribute)
	if pkt.NAttributes() != 1 {
		t.Errorf("NAttributes incorrect: %d\n", pkt.NAttributes())
	}
	if attribute.String() != "TEST ROUTINE" {
		t.Error("attribute invalid")
	}

	attribute, err = MakeFingerprintAttribute(&pkt)
	if err != nil {
		t.Error(err)
	}
	pkt.AddAttribute(attribute)
	if pkt.NAttributes() != 2 {
		t.Errorf("NAttributes incorrect: %d\n", pkt.NAttributes())
	}

	attribute, err = MakeChangeRequestAttribute(&pkt, true, true)
	if err != nil {
		t.Error(err)
	}
	pkt.AddAttribute(attribute)
	if pkt.NAttributes() != 3 {
		t.Errorf("NAttributes incorrect: %d\n", pkt.NAttributes())
	}
}
