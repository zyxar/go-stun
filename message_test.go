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
	id := [...]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12}
	message, err := CreateEmptyMessage(TYPE_BINDING_REQUEST, 0, id)
	if err != nil {
		t.Error(err)
	}
	if message.Length() != 0 {
		t.Error("wrong message length")
	}
	if bytes.Compare(message.Encode(), head) != 0 {
		t.Error("CreateEmptyMessage failed")
	}
	message2, _ := NewMessage(head)
	if bytes.Compare(message2.Encode(), message.Encode()) != 0 {
		t.Error("NewMessage failed")
	}

	data := []byte{
		0x01, 0x01, 0x00, 0x44, 0x21, 0x12, 0xa4, 0x42,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x10, 0x11, 0x12, 0x00, 0x01, 0x00, 0x08,
		0x00, 0x01, 0xbe, 0x04, 0x0a, 0xef, 0x0a, 0x07,
		0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x0d, 0x97,
		0x0a, 0xef, 0x0a, 0x07, 0x00, 0x05, 0x00, 0x08,
		0x00, 0x01, 0x0d, 0x96, 0x7f, 0x00, 0x00, 0x01,
		0x80, 0x20, 0x00, 0x08, 0x00, 0x01, 0x9f, 0x16,
		0x2b, 0xfd, 0xae, 0x45, 0x80, 0x22, 0x00, 0x10,
		0x56, 0x6f, 0x76, 0x69, 0x64, 0x61, 0x2e, 0x6f,
		0x72, 0x67, 0x20, 0x30, 0x2e, 0x39, 0x36, 0x00,
	}
	resp, err := NewMessage(data)
	if err != nil {
		t.Error(err)
	}
	if resp.NAttributes() != 5 {
		t.Error("Wrong number of attributes")
	}
	if resp.Type().Value() != TYPE_BINDING_RESPONSE {
		t.Error("Wrong message type")
	}
	if resp.Length() != 0x44 || resp.Length() != uint16(len(data)-20) {
		t.Errorf("Wront message length: %d", resp.Length())
	}
	if bytes.Compare(data, resp.Encode()) != 0 {
		t.Error("message encode failed")
	}
}

func TestPacketAddAttr(t *testing.T) {
	id := [...]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12}
	message, err := CreateEmptyMessage(TYPE_BINDING_REQUEST, 0, id)
	if message.NAttributes() != 0 {
		t.Errorf("NAttributes incorrect: %d\n", message.NAttributes())
	}
	if err = message.AddSoftwareAttribute("TEST ROUTINE"); err != nil {
		t.Error(err)
	}
	if message.Length() != 12+4 {
		t.Errorf("AddAttribute breaks message length, %d", message.Length())
	}
	if message.NAttributes() != 1 {
		t.Errorf("NAttributes incorrect: %d\n", message.NAttributes())
	}
	if err = message.AddChangeRequestAttribute(true, true); err != nil {
		t.Error(err)
	}
	if message.Length() != 12+4+4+4 {
		t.Errorf("AddAttribute breaks message length, %d", message.Length())
	}
	if message.NAttributes() != 2 {
		t.Errorf("NAttributes incorrect: %d\n", message.NAttributes())
	}
	if err = message.AddFingerprintAttribute(); err != nil {
		t.Error(err)
	}
	if message.Length() != 12+4+4+4+4+4 {
		t.Errorf("AddAttribute breaks message length, %d", message.Length())
	}
	if message.NAttributes() != 3 {
		t.Errorf("NAttributes incorrect: %d\n", message.NAttributes())
	}
}
