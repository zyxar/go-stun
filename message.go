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
	"encoding/binary"
	"errors"
	"fmt"
)

type MessageBody []Attribute
type Message struct {
	m []byte
	b MessageBody // cache
}

type Type interface {
	String() string
	Value() uint16
}

type messageType uint16

func (m messageType) Value() uint16  { return uint16(m) }
func (m messageType) String() string { return message_types[m.Value()] }

func (this *Message) Type() Type              { return messageType(binary.BigEndian.Uint16(this.m[0:2])) }
func (this *Message) Length() uint16          { return binary.BigEndian.Uint16(this.m[2:4]) }
func (this *Message) Id() []byte              { return this.m[8:20] }
func (this *Message) Encode() []byte          { return this.m }
func (this *Message) NAttributes() int        { return len(this.b) }
func (this *Message) Attributes() []Attribute { return this.b }

// func (this *Message) Head() []byte                { return this.m[:20] }
// func (this *Message) Body() MessageBody           { return this.b }
// func (this *Message) Payload() []byte             { return this.m[20:] }

func (this *Message) Attribute(i int) Attribute {
	if i >= len(this.b) {
		return nil
	}
	return this.b[i]
}

func (this Message) String() string {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("% -14s: 0x%04x (%s)\n", "Type", this.Type().Value(), this.Type().String()))
	buffer.WriteString(fmt.Sprintf("% -14s: %d (0x%04x)\n", "Length", this.Length(), this.Length()))
	buffer.WriteString(fmt.Sprintf("% -14s: % x\n", "Id", this.Id()))
	buffer.WriteString(fmt.Sprintf("% -14s: %d\n", "NAttributes", this.NAttributes()))
	for i := 0; i < this.NAttributes(); i++ {
		attr := this.Attribute(i)
		buffer.WriteString(fmt.Sprintf("% -14s: %d (total length %d)\n", "Attribute No.", i, attr.Length()+4))
		buffer.WriteString(fmt.Sprintf("% -14s: 0x%04x (%s)\n", "Type", attr.Type().Value(), attr.Type().String()))
		buffer.WriteString(fmt.Sprintf("% -14s: %d\n", "Length", attr.Length()))
		buffer.WriteString(fmt.Sprintf("% -14s: % x\n", "Value", attr.Value()))
		buffer.WriteString(fmt.Sprintf("% -14s: %s\n", "Decode", attr.String()))
	}
	return buffer.String()
}

func (this Message) HexString() string {
	var buffer bytes.Buffer
	for i := 0; i < len(this.m); i++ {
		if i%16 == 0 {
			buffer.WriteByte('\t')
		}
		buffer.WriteString(fmt.Sprintf("%02x", this.m[i]))
		if (i+1)%16 == 0 {
			buffer.WriteByte('\n')
		} else if (i+1)%2 == 0 {
			buffer.WriteByte(' ')
		}
	}
	if len(this.m)%16 != 0 {
		buffer.WriteByte('\n')
	}
	return buffer.String()
}

func (this *Message) hasAttribute(a uint16) int {
	for i := 0; i < this.NAttributes(); i++ {
		if this.Attribute(i).Type().Value() == a {
			return i
		}
	}
	return -1
}

func (this *Message) MappedAddressIndex() int {
	return this.hasAttribute(ATTRIBUTE_MAPPED_ADDRESS)
}

func (this *Message) ChangedAddressIndex() int {
	return this.hasAttribute(ATTRIBUTE_CHANGED_ADDRESS)
}

func (this *Message) XorMappedAddressIndex() int {
	index := this.hasAttribute(ATTRIBUTE_XOR_MAPPED_ADDRESS)
	if index == -1 {
		return this.hasAttribute(ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP)
	}
	return index
}

func NewMessage(b []byte) (*Message, error) {
	if len(b) < 20 || len(b)-20 < int(binary.BigEndian.Uint16(b[2:4])) {
		return nil, invalidMsgLengthErr
	}
	if binary.BigEndian.Uint32(b[4:8]) != MAGIC_COOKIE {
		return nil, invalidCookieErr
	}
	attributes := make([]Attribute, 0, 10)
	var pos uint16 = 20
	for pos < uint16(len(b)) {
		attribute, err := ParseAttribute(b[pos:])
		if nil != err {
			return nil, err
		}
		attributes = append(attributes, attribute)
		pos += uint16(attribute.Length() + 4)
	}
	return &Message{m: b, b: attributes}, nil
}

func CreateEmptyMessage(_type uint16, _length uint16, _id [12]byte) (*Message, error) {
	if _, ok := message_types[_type]; !ok {
		return nil, invalidMsgTypeErr
	}
	_length += 20
	m := make([]byte, 20, _length)
	binary.BigEndian.PutUint16(m[:2], _type)
	// binary.BigEndian.PutUint16(m[2:4], 0)
	binary.BigEndian.PutUint32(m[4:8], MAGIC_COOKIE)
	copy(m[8:20], _id[:])
	return &Message{
		m: m,
		b: make([]Attribute, 0, 10),
	}, nil
}

func (this *Message) AddAttribute(attr Attribute) {
	this.m = append(this.m, attr.Encode(nil)...)
	this.b = append(this.b, attr)
	binary.BigEndian.PutUint16(this.m[2:4], this.Length()+uint16(attr.Length()+4)) // update length
}

func (this *Message) AddFingerprintAttribute() error {
	crc := crc32Checksum(this.m)
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, crc)
	if attr, err := parseAttribute(ATTRIBUTE_FINGERPRINT, b); err != nil {
		return err
	} else {
		this.AddAttribute(attr)
	}
	return nil
}

func (this *Message) AddSoftwareAttribute(name string) error {
	length := len(name)
	if length > 763 {
		return errors.New("name too long")
	}
	if attr, err := parseAttribute(ATTRIBUTE_SOFTWARE, []byte(name)); err != nil {
		return err
	} else {
		this.AddAttribute(attr)
	}
	return nil
}

func (this *Message) AddChangeRequestAttribute(changIP, changPort bool) error {
	var value []byte = make([]byte, 4, 4)
	// RFC 3489: The CHANGE-REQUEST attribute is used by the client to request that
	// the server use a different address and/or port when sending the
	// response.  The attribute is 32 bits long, although only two bits (A and B) are used.
	if changIP {
		value[3] = value[3] | 0x04
	} // b:0100
	if changPort {
		value[3] = value[3] | 0x02
	} // b:0010
	if attr, err := parseAttribute(ATTRIBUTE_CHANGE_REQUEST, value); err != nil {
		return err
	} else {
		this.AddAttribute(attr)
	}
	return nil
}

var (
	invalidCookieErr    = errors.New("invalid cookie value")
	invalidMsgTypeErr   = errors.New("invalid message type")
	invalidMsgLengthErr = errors.New("invalid message length")
)
