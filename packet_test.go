// Copyright (C) 2015 Markus Tzoe
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package stun

import (
	"bytes"
	"testing"
)

func TestPacketCreation(t *testing.T) {
	head := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12}
	packet, err := newPacket(TYPE_BINDING_REQUEST, 0, head[4:])
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare(packet.Bytes(), head) != 0 {
		t.Error("makePacket failed")
	}
	packet2, _ := NewPacket(head)
	if bytes.Compare(packet2.Bytes(), head) != 0 {
		t.Error("NewPacket failed")
	}

	data := []byte{
		0x01, 0x01, 0x00, 0x88,
		0x21, 0x12, 0xa4, 0x42,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x10, 0x11, 0x12,
		0x00, 0x01, 0x00, 0x08,
		0x00, 0x01, 0xcd, 0xf2,
		0x72, 0x5c, 0x75, 0x8d,
		0x00, 0x04, 0x00, 0x08,
		0x00, 0x01, 0x0d, 0x96,
		0x40, 0x18, 0x23, 0xc9,
		0x00, 0x05, 0x00, 0x08,
		0x00, 0x01, 0x0d, 0x97,
		0x40, 0x18, 0x23, 0xf8,
		0x80, 0x20, 0x00, 0x08,
		0x00, 0x01, 0xec, 0xe0,
		0x53, 0x4e, 0xd1, 0xcf,
		0x80, 0x22, 0x00, 0x10,
		0x56, 0x6f, 0x76, 0x69,
		0x64, 0x61, 0x2e, 0x6f,
		0x72, 0x67, 0x20, 0x30,
		0x2e, 0x39, 0x36, 0x00}
	packet3, err := NewPacket(data)
	if err != nil {
		t.Error(err)
	}
	if packet3.NAttributes() != 5 {
		t.Error("Wrong number of attributes")
	}
	if packet3._type != TYPE_BINDING_RESPONSE {
		t.Error("Wrong packet type")
	}
	if packet3.length != 0x88 {
		t.Errorf("Wront packet length: %d", packet3.length)
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
	var err error
	if err = pkt.AddSoftwareAttribute("TEST ROUTINE"); err != nil {
		t.Error(err)
	}
	if pkt.NAttributes() != 1 {
		t.Errorf("NAttributes incorrect: %d\n", pkt.NAttributes())
	}
	if err = pkt.AddChangeRequestAttribute(true, true); err != nil {
		t.Error(err)
	}
	if pkt.NAttributes() != 2 {
		t.Errorf("NAttributes incorrect: %d\n", pkt.NAttributes())
	}
	if err = pkt.AddFingerprintAttribute(); err != nil {
		t.Error(err)
	}
	if pkt.NAttributes() != 3 {
		t.Errorf("NAttributes incorrect: %d\n", pkt.NAttributes())
	}
}
