// Copyright (C) 2015 Markus Tzoe
// Copyright (C) 2012 Denis BEURIVE
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
	"net"
)

// This type represents a STUN UDP packet.
// RFC5389: The message length MUST contain the size, in bytes, of the message
//           **not** including the 20-byte STUN header.  Since all STUN attributes are
//           padded to a multiple of 4 bytes, the last 2 bits of this field are
//           always zero.  This provides another way to distinguish STUN packets
//           from packets of other protocols.
type Packet struct {
	_type      uint16       // Type of the packet (constant TYPE_...).
	length     uint16       // Lentgth of the packet. 16 bits
	cookie     uint32       // The magik cookie (32 bits)
	id         [12]byte     // The STUN's ID. 96 bits (12 bytes)
	attributes []_Attribute // The list of attributes included in the packet.
}

// Add an attribute to the packet.
//
// INPUT
// - attr: the attribute to add
func (this *Packet) AddAttribute(attr _Attribute) {
	this.attributes = append(this.attributes, attr)
	// Add the *TOTAL* length of the added attribute.
	// (Padded) value + header

	if RFC3489 == rfc {
		this.length += attr.Length + 4
		if 0 != this.length%4 {
			panic("STUN is configured to be compliant with RFC 3489. All attributes' lengths must be multiples of 4.")
		}
	} else {
		this.length += nextBoundary(attr.Length) + 4
	}
}

// Return the number of attributes in the packet.
//
// OUTPUT
// - The number of attributes in the packet.
func (this *Packet) NAttributes() int {
	return len(this.attributes)
}

// Get a an attribute from the packet.
//
// INPUT
// - i: index of the attribute within the packet.
//
// OUTPUT
// - The attribute.
func (this *Packet) Attribute(i int) _Attribute {
	return this.attributes[i]
}

// This function creates a sequence of bytes from a STUN packet, that can be sent to the network.
//
// OUTPUT
// - The sequence of bytes.
func (this Packet) Encode() []byte {
	length := 20
	for i := 0; i < len(this.attributes); i++ {
		length += 4 + len(this.attributes[i].Value)
	}
	if length > 65535 {
		return nil
	}
	p := make([]byte, length)
	binary.BigEndian.PutUint16(p[0:2], this._type)  // Add the message's type.
	binary.BigEndian.PutUint16(p[2:4], this.length) // Add the packet's length. // Note: at this point, set the length to 0.
	binary.BigEndian.PutUint32(p[4:8], this.cookie) // Add the magic cookie.
	copy(p[8:], this.id[:])                         // Add the transaction ID.
	pos := 20
	for i := 0; i < len(this.attributes); i++ { // Add attributes.
		binary.BigEndian.PutUint16(p[pos:pos+2], this.attributes[i].Type)
		pos += 2
		binary.BigEndian.PutUint16(p[pos:pos+2], this.attributes[i].Length) // We set the *real* length, not the padded one.
		pos += 2
		copy(p[pos:], this.attributes[i].Value) // Please keep in mind that values contain padding.
		pos += len(this.attributes[i].Value)
	}
	binary.BigEndian.PutUint16(p[2:4], this.length) // var length uint16 = uint16(len(p) - 20)
	return p
}

// This function converts a sequence of bytes into a STUN packet.
//
// INPUT
// - b: the sequence of bytes.
//
// OUTPUT
// - The STUN packet.
// - The error flag.
//
// NOTE
// The length of the packet is initialized to the value 20, which is the length of the header.
func NewPacket(b []byte) (*Packet, error) {
	return newPacket(binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4]), b[4:])
}

func newPacket(_type uint16, _length uint16, b []byte) (*Packet, error) {
	b_len := len(b)
	if b_len < 20-4 || b_len > 65535-4 {
		return nil, fmt.Errorf("Invalid STUN packet: %d bytes", b_len)
	}
	pkt := Packet{
		_type:      _type,
		cookie:     MAGIC_COOKIE,
		length:     _length, // Header (20 bytes) is **not** included.
		attributes: make([]_Attribute, 0, 10),
	}
	// pkt.cookie = binary.BigEndian.Uint32(b[0:4])
	copy(pkt.id[:], b[4:16])

	// Get attributes
	// For RFC 5389 only:
	//     Please keep in mind that values contain padding.
	//     Lengthes of attribltes' values don't include the padding's length.
	var pos uint16 = 16
	for pos < uint16(b_len) {
		vtype := binary.BigEndian.Uint16(b[pos : pos+2])    // Type of the attribute.
		length := binary.BigEndian.Uint16(b[pos+2 : pos+4]) // Length of the attribute (without the padding !!!!!!)
		value := b[pos+4 : pos+4+length]                    // The value.
		attribute, err := makeAttribute(vtype, value)
		if nil != err {
			return nil, err
		}
		pkt.attributes = append(pkt.attributes, attribute)

		// 4 bytes: for the attribute's header.
		if RFC3489 == rfc {
			pos += 4 + length
			if 0 != pos%4 {
				return nil, fmt.Errorf("Invalid value length in attribute")
			}
		} else {
			// RFC 5389 only: we must take care of the padding.
			pos += 4 + nextBoundary(length)
		}
	}

	return &pkt, nil
}

// This function generates a textual representation of a given STUN packet.
//
// OUTPUT
// - The textual representation.
func (this Packet) String() string {
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("% -14s: 0x%04x (%s)\n", "Type", this._type, message_types[this._type]))
	buffer.WriteString(fmt.Sprintf("% -14s: %d (0x%04x)\n", "Length", this.length, this.length))
	buffer.WriteString(fmt.Sprintf("% -14s: 0x%x\n", "Cookie", this.cookie))
	buffer.WriteString(fmt.Sprintf("% -14s: % x\n", "ID", this.id[:]))
	buffer.WriteString(fmt.Sprintf("% -14s: %d\n", "NAttributes", this.NAttributes()))

	for i := 0; i < this.NAttributes(); i++ {
		attr := this.Attribute(i)
		buffer.WriteString(fmt.Sprintf("% -14s: %d (total length %d)\n", "Attribute No.", i+1, attr.Length+4))
		buffer.WriteString(fmt.Sprintf("% -14s: 0x%04x (%s)\n", "Type", attr.Type, attribute_names[attr.Type]))
		buffer.WriteString(fmt.Sprintf("% -14s: %d\n", "length", attr.Length))
		buffer.WriteString(fmt.Sprintf("% -14s: % x\n", "Value", attr.Value))
		buffer.WriteString(fmt.Sprintf("% -14s: %s\n", "Decode", attr.String()))
	}
	return buffer.String()
}

// This function generates a nicely formatted representation of a list of bytes received from the network.
//
// INPUT
// - p: the list of bytes extracted from the network.
//
// OUPUT
// - The nicely formatted representation if the given list of bytes.
func (this Packet) HexString() string {
	p := this.Encode()
	var buffer bytes.Buffer
	length := len(p)
	rest := length % 4
	nb := (length - rest) / 4

	for i := 0; i < nb; i++ {
		buffer.WriteString(fmt.Sprintf("\t%02x %02x %02x %02x\n", p[i*4], p[i*4+1], p[i*4+2], p[i*4+3]))
	}
	if rest > 0 {
		buffer.WriteByte('\t')
		for i := 0; i < 4; i++ {
			buffer.WriteByte(' ')
			if nb*4+i >= len(p) {
				buffer.WriteByte(' ')
			} else {
				buffer.WriteString(fmt.Sprintf("%02x", p[nb*4+i]))
			}
		}
		buffer.WriteByte('\n')
	}
	return buffer.String()
}

// This function extracts the mapped address from a packet.
//
// OUTPUT
// - This flag indicates whether the packet contains the searched attribute.
//   + true: the packet contains the searched attribute.
//   + false: the packet does not contain the searched attribute.
// - The IP family.
// - The IP address.
// - The port number.
// - The error flag.
func (this Packet) MappedAddress() (uint16, net.IP, uint16, error) {
	for i := 0; i < this.NAttributes(); i++ {
		attr := this.Attribute(i)
		if ATTRIBUTE_MAPPED_ADDRESS != attr.Type {
			continue
		}
		f, ip, p := attr.decode()
		return f, ip, p, nil
	}
	return 0, nil, 0, errors.New("mapped address not found")
}

// This function extracts the "changed" address from a packet.
//
// OUTPUT
// - This flag indicates whether the packet contains the searched attribute.
//   + true: the packet contains the searched attribute.
//   + false: the packet does not contain the searched attribute.
// - The IP family.
// - The IP address.
// - The port number.
// - The error flag.
func (this Packet) ChangedAddress() (uint16, net.IP, uint16, error) {
	for i := 0; i < this.NAttributes(); i++ {
		attr := this.Attribute(i)
		if ATTRIBUTE_CHANGED_ADDRESS != attr.Type {
			continue
		}
		f, ip, p := attr.decode()
		return f, ip, p, nil
	}
	return 0, nil, 0, errors.New("changed address not found")
}

// This function extracts the xored mapped address from a packet.
//
// OUTPUT
// - This flag indicates whether the packet contains the searched attribute.
//   + true: the packet contains the searched attribute.
//   + false: the packet does not contain the searched attribute.
// - The IP family.
// - The IP address.
// - The port number.
// - The error flag.
func (this Packet) XorMappedAddress() (uint16, net.IP, uint16, error) {
	for i := 0; i < this.NAttributes(); i++ {
		attr := this.Attribute(i)
		if (ATTRIBUTE_XOR_MAPPED_ADDRESS != attr.Type) && (ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP != attr.Type) {
			continue
		}
		family, _, _, xip, xport, err := attr.XorMappedAddress()
		return family, xip, xport, err
	}
	return 0, nil, 0, errors.New("xor-mapped address not found")
}

// This function adds a "FINGERPRINT" attribute to packet.
// See http://golang.org/src/pkg/hash/crc32/crc32.go
//
// OUTPUT
// - The error flag.
//
// WARNING
// The FINGERPRINT attribute should be the last attribute of the STUN packet.
func (this *Packet) AddFingerprintAttribute() error {
	crc := crc32Checksum(this.Encode())
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, crc)
	if attr, err := makeAttribute(ATTRIBUTE_FINGERPRINT, b); err != nil {
		return err
	} else {
		this.AddAttribute(attr)
	}
	return nil
}

// This function adds a "SOFTWARE" attribute to packet.
//
// INPUT
// - name: name of the software.
//
// OUTPUT
// - The error flag.
func (this *Packet) AddSoftwareAttribute(name string) error {
	length := len(name)
	if length > 763 {
		return errors.New("Software's name if too long (more than 763 bytes!)")
	}
	var b []byte
	if length%4 == 0 {
		b = []byte(name)
	} else {
		b = make([]byte, nextBoundary(uint16(length)))
		copy(b[:length], []byte(name))
	}
	if attr, err := makeAttribute(ATTRIBUTE_SOFTWARE, b); err != nil {
		return err
	} else {
		this.AddAttribute(attr)
	}
	return nil
}

// This function adds a "CHANGE RESQUEST" attribute to packet.
//
// INPUT
// - changIP: shall we change the IP address?
// - changPort: shall we change the port number?
//
// OUTPUT
// - The error flag.
func (this *Packet) AddChangeRequestAttribute(changIP, changPort bool) error {
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
	if attr, err := makeAttribute(ATTRIBUTE_CHANGE_REQUEST, value); err != nil {
		return err
	} else {
		this.AddAttribute(attr)
	}
	return nil
}
