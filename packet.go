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
	"fmt"
	"strings"
)

const (
	// STUN's magic cookie.
	MAGIC_COOKIE = 0x2112A442

	/* ------------------------------------------------------------------------------------------------ */
	/* Packet' types.                                                                                   */
	/* See: Session Traversal Utilities for NAT (STUN) Parameters                                       */
	/*      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml                         */
	/* ------------------------------------------------------------------------------------------------ */
	TYPE_BINDING_REQUEST                   = 0x0001
	TYPE_BINDING_RESPONSE                  = 0x0101
	TYPE_BINDING_ERROR_RESPONSE            = 0x0111
	TYPE_SHARED_SECRET_REQUEST             = 0x0002
	TYPE_SHARED_SECRET_RESPONSE            = 0x0102
	TYPE_SHARED_ERROR_RESPONSE             = 0x0112
	TYPE_ALLOCATE                          = 0x0003
	TYPE_ALLOCATE_RESPONSE                 = 0x0103
	TYPE_ALLOCATE_ERROR_RESPONSE           = 0x0113
	TYPE_REFRESH                           = 0x0004
	TYPE_REFRESH_RESPONSE                  = 0x0104
	TYPE_REFRESH_ERROR_RESPONSE            = 0x0114
	TYPE_SEND                              = 0x0006
	TYPE_SEND_RESPONSE                     = 0x0106
	TYPE_SEND_ERROR_RESPONSE               = 0x0116
	TYPE_DATA                              = 0x0007
	TYPE_DATA_RESPONSE                     = 0x0107
	TYPE_DATA_ERROR_RESPONSE               = 0x0117
	TYPE_CREATE_PERMISIION                 = 0x0008
	TYPE_CREATE_PERMISIION_RESPONSE        = 0x0108
	TYPE_CREATE_PERMISIION_ERROR_RESPONSE  = 0x0118
	TYPE_CHANNEL_BINDING                   = 0x0009
	TYPE_CHANNEL_BINDING_RESPONSE          = 0x0109
	TYPE_CHANNEL_BINDING_ERROR_RESPONSE    = 0x0119
	TYPE_CONNECT                           = 0x000A
	TYPE_CONNECT_RESPONSE                  = 0x010A
	TYPE_CONNECT_ERROR_RESPONSE            = 0x011A
	TYPE_CONNECTION_BIND                   = 0x000B
	TYPE_CONNECTION_BIND_RESPONSE          = 0x010B
	TYPE_CONNECTION_BIND_ERROR_RESPONSE    = 0x011B
	TYPE_CONNECTION_ATTEMPT                = 0x000C
	TYPE_CONNECTION_ATTEMPT_RESPONSE       = 0x010C
	TYPE_CONNECTION_ATTEMPT_ERROR_RESPONSE = 0x011C

	/* ------------------------------------------------------------------------------------------------ */
	/* Error values.                                                                                    */
	/* See: Session Traversal Utilities for NAT (STUN) Parameters                                       */
	/*      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml                         */
	/* ------------------------------------------------------------------------------------------------ */
	ERROR_TRY_ALTERNATE                  = 300
	ERROR_BAD_REQUEST                    = 400
	ERROR_UNAUTHORIZED                   = 401
	ERROR_UNASSIGNED_402                 = 402
	ERROR_FORBIDDEN                      = 403
	ERROR_UNKNOWN_ATTRIBUTE              = 420
	ERROR_ALLOCATION_MISMATCH            = 437
	ERROR_STALE_NONCE                    = 438
	ERROR_UNASSIGNED_439                 = 439
	ERROR_ADDRESS_FAMILY_NOT_SUPPORTED   = 440
	ERROR_WRONG_CREDENTIALS              = 441
	ERROR_UNSUPPORTED_TRANSPORT_PROTOCOL = 442
	ERROR_PEER_ADDRESS_FAMILY_MISMATCH   = 443
	ERROR_CONNECTION_ALREADY_EXISTS      = 446
	ERROR_CONNECTION_TIMEOUT_OR_FAILURE  = 447
	ERROR_ALLOCATION_QUOTA_REACHED       = 486
	ERROR_ROLE_CONFLICT                  = 487
	ERROR_SERVER_ERROR                   = 500
	ERROR_INSUFFICIENT_CAPACITY          = 508
)

// This map associates an type's value to a type's name.
var message_types = map[uint16]string{
	TYPE_BINDING_REQUEST:                   "BINDING_REQUEST",
	TYPE_BINDING_RESPONSE:                  "BINDING_RESPONSE",
	TYPE_BINDING_ERROR_RESPONSE:            "BINDING_ERROR_RESPONSE",
	TYPE_SHARED_SECRET_REQUEST:             "SHARED_SECRET_REQUEST",
	TYPE_SHARED_SECRET_RESPONSE:            "SHARED_SECRET_RESPONSE",
	TYPE_SHARED_ERROR_RESPONSE:             "SHARED_ERROR_RESPONSE",
	TYPE_ALLOCATE:                          "ALLOCATE",
	TYPE_ALLOCATE_RESPONSE:                 "ALLOCATE_RESPONSE",
	TYPE_ALLOCATE_ERROR_RESPONSE:           "ALLOCATE_ERROR_RESPONSE",
	TYPE_REFRESH:                           "REFRESH",
	TYPE_REFRESH_RESPONSE:                  "REFRESH_RESPONSE",
	TYPE_REFRESH_ERROR_RESPONSE:            "REFRESH_ERROR_RESPONSE",
	TYPE_SEND:                              "SEND",
	TYPE_SEND_RESPONSE:                     "SEND_RESPONSE",
	TYPE_SEND_ERROR_RESPONSE:               "SEND_ERROR_RESPONSE",
	TYPE_DATA:                              "DATA",
	TYPE_DATA_RESPONSE:                     "DATA_RESPONSE",
	TYPE_DATA_ERROR_RESPONSE:               "DATA_ERROR_RESPONSE",
	TYPE_CREATE_PERMISIION:                 "CREATE_PERMISIION",
	TYPE_CREATE_PERMISIION_RESPONSE:        "CREATE_PERMISIION_RESPONSE",
	TYPE_CREATE_PERMISIION_ERROR_RESPONSE:  "CREATE_PERMISIION_ERROR_RESPONSE",
	TYPE_CHANNEL_BINDING:                   "CHANNEL_BINDING",
	TYPE_CHANNEL_BINDING_RESPONSE:          "CHANNEL_BINDING_RESPONSE",
	TYPE_CHANNEL_BINDING_ERROR_RESPONSE:    "CHANNEL_BINDING_ERROR_RESPONSE",
	TYPE_CONNECT:                           "CONNECT",
	TYPE_CONNECT_RESPONSE:                  "CONNECT_RESPONSE",
	TYPE_CONNECT_ERROR_RESPONSE:            "CONNECT_ERROR_RESPONSE",
	TYPE_CONNECTION_BIND:                   "CONNECTION_BIND",
	TYPE_CONNECTION_BIND_RESPONSE:          "CONNECTION_BIND_RESPONSE",
	TYPE_CONNECTION_BIND_ERROR_RESPONSE:    "CONNECTION_BIND_ERROR_RESPONSE",
	TYPE_CONNECTION_ATTEMPT:                "CONNECTION_ATTEMPT",
	TYPE_CONNECTION_ATTEMPT_RESPONSE:       "CONNECTION_ATTEMPT_RESPONSE",
	TYPE_CONNECTION_ATTEMPT_ERROR_RESPONSE: "CONNECTION_ATTEMPT_ERROR_RESPONSE",
}

// This map associates an error's code with an error's name.
var error_names = map[uint16]string{
	ERROR_TRY_ALTERNATE:                  "TRY_ALTERNATE",
	ERROR_BAD_REQUEST:                    "BAD_REQUEST",
	ERROR_UNAUTHORIZED:                   "UNAUTHORIZED",
	ERROR_UNASSIGNED_402:                 "UNASSIGNED_402",
	ERROR_FORBIDDEN:                      "FORBIDDEN",
	ERROR_UNKNOWN_ATTRIBUTE:              "UNKNOWN_ATTRIBUTE",
	ERROR_ALLOCATION_MISMATCH:            "ALLOCATION_MISMATCH",
	ERROR_STALE_NONCE:                    "STALE_NONCE",
	ERROR_UNASSIGNED_439:                 "UNASSIGNED_439",
	ERROR_ADDRESS_FAMILY_NOT_SUPPORTED:   "ADDRESS_FAMILY_NOT_SUPPORTED",
	ERROR_WRONG_CREDENTIALS:              "WRONG_CREDENTIALS",
	ERROR_UNSUPPORTED_TRANSPORT_PROTOCOL: "UNSUPPORTED_TRANSPORT_PROTOCOL",
	ERROR_PEER_ADDRESS_FAMILY_MISMATCH:   "PEER_ADDRESS_FAMILY_MISMATCH",
	ERROR_CONNECTION_ALREADY_EXISTS:      "CONNECTION_ALREADY_EXISTS",
	ERROR_CONNECTION_TIMEOUT_OR_FAILURE:  "CONNECTION_TIMEOUT_OR_FAILURE",
	ERROR_ALLOCATION_QUOTA_REACHED:       "ALLOCATION_QUOTA_REACHED",
	ERROR_ROLE_CONFLICT:                  "ROLE_CONFLICT",
	ERROR_SERVER_ERROR:                   "SERVER_ERROR",
	ERROR_INSUFFICIENT_CAPACITY:          "INSUFFICIENT_CAPACITY",
}

/* ------------------------------------------------------------------------------------------------ */
/* Types.                                                                                           */
/* ------------------------------------------------------------------------------------------------ */

// This type represents a STUN UDP packet.
type Packet struct {
	// Type of the packet (constant TYPE_...).
	_type uint16
	// RFC5389: The message length MUST contain the size, in bytes, of the message
	//           **not** including the 20-byte STUN header.  Since all STUN attributes are
	//           padded to a multiple of 4 bytes, the last 2 bits of this field are
	//           always zero.  This provides another way to distinguish STUN packets
	//           from packets of other protocols.
	length     uint16      // Lentgth of the packet. 16 bits
	cookie     uint32      // The magik cookie (32 bits)
	id         [12]byte    // The STUN's ID. 96 bits (12 bytes)
	attributes []Attribute // The list of attributes included in the packet.
}

/* ------------------------------------------------------------------------------------------------ */
/* API                                                                                              */
/* ------------------------------------------------------------------------------------------------ */

// Add an attribute to the packet.
//
// INPUT
// - attr: the attribute to add
func (packet *Packet) AddAttribute(attr Attribute) {
	packet.attributes = append(packet.attributes, attr)
	// Add the *TOTAL* length of the added attribute.
	// (Padded) value + header

	if RFC3489 == rfc {
		packet.length += attr.Length + 4
		if 0 != packet.length%4 {
			panic("STUN is configured to be compliant with RFC 3489. All attributes' lengths must be multiples of 4.")
		}
	} else {
		packet.length += nextBoundary(attr.Length) + 4
	}
}

// Return the number of attributes in the packet.
//
// OUTPUT
// - The number of attributes in the packet.
func (packet *Packet) NAttributes() int {
	return len(packet.attributes)
}

// Get a an attribute from the packet.
//
// INPUT
// - i: index of the attribute within the packet.
//
// OUTPUT
// - The attribute.
func (packet *Packet) Attribute(i int) Attribute {
	return packet.attributes[i]
}

// This function creates a sequence of bytes from a STUN packet, that can be sent to the network.
//
// OUTPUT
// - The sequence of bytes.
func (packet Packet) Bytes() []byte {
	length := 20
	for i := 0; i < len(packet.attributes); i++ {
		length += 4 + len(packet.attributes[i].Value)
	}
	if length > 65535 {
		return nil
	}
	p := make([]byte, length)
	binary.BigEndian.PutUint16(p[0:2], packet._type)  // Add the message's type.
	binary.BigEndian.PutUint16(p[2:4], packet.length) // Add the packet's length. // Note: at this point, set the length to 0.
	binary.BigEndian.PutUint32(p[4:8], packet.cookie) // Add the magic cookie.
	copy(p[8:], packet.id[:])                         // Add the transaction ID.
	pos := 20
	for i := 0; i < len(packet.attributes); i++ { // Add attributes.
		binary.BigEndian.PutUint16(p[pos:pos+2], packet.attributes[i].Type)
		pos += 2
		binary.BigEndian.PutUint16(p[pos:pos+2], packet.attributes[i].Length) // We set the *real* length, not the padded one.
		pos += 2
		copy(p[pos:], packet.attributes[i].Value) // Please keep in mind that values contain padding.
		pos += len(packet.attributes[i].Value)
	}
	binary.BigEndian.PutUint16(p[2:4], packet.length) // var length uint16 = uint16(len(p) - 20)
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
func MakePacket(b []byte) (Packet, error) {
	return makePacket(binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4]), b[4:])
}

func makePacket(_type uint16, _length uint16, b []byte) (Packet, error) {
	pkt := Packet{
		_type:      _type,
		cookie:     MAGIC_COOKIE,
		length:     _length, // Header (20 bytes) is **not** included.
		attributes: make([]Attribute, 0, 10),
	}
	b_len := len(b)
	if b_len < 20-4 {
		return pkt, fmt.Errorf("The given list of bytes does not represent a STUN packet. Only %d bytes.", b_len)
	}
	if b_len > 65535-4 {
		return pkt, fmt.Errorf("The given list of bytes does not represent a STUN packet. %d bytes.", b_len)
	}

	// pkt.cookie = binary.BigEndian.Uint32(b[0:4])
	copy(pkt.id[:], b[4:16])

	// Get attributes
	// For RFC 5389 only:
	//     Please keep in mind that values contain padding.
	//     Lengthes of attribltes' values don't include the padding's length.
	var pos uint16 = 18
	for pos < uint16(b_len) {
		vtype := binary.BigEndian.Uint16(b[pos : pos+2])    // Type of the attribute.
		length := binary.BigEndian.Uint16(b[pos+2 : pos+4]) // Length of the attribute (without the padding !!!!!!)
		value := b[pos+4 : pos+4+length]                    // The value.
		attribute, err := MakeAttribute(vtype, value, &pkt)
		if nil != err {
			return pkt, err
		}
		pkt.AddAttribute(attribute)

		// 4 bytes: for the attribute's header.
		if RFC3489 == rfc {
			pos += 4 + length
			if 0 != pos%4 {
				return pkt, fmt.Errorf("STUN is configured to be compliant with RFC 3489! Value's length must be a multiple of 4 bytes!")
			}
		} else {
			// RFC 5389 only: we must take care of the padding.
			pos += 4 + nextBoundary(length)
		}
	}

	return pkt, nil
}

// This function generates a textual representation of a given STUN packet.
//
// OUTPUT
// - The textual representation.
func (packet Packet) String() string {
	var buffer bytes.Buffer
	indent := strings.Repeat(" ", 4)
	mt, ok := message_types[packet._type]
	if !ok {
		mt = "Unknown message type"
	}
	buffer.WriteString(fmt.Sprintf("%s% -21s: 0x%04x (%s)\n", indent, "Type", packet._type, mt))
	buffer.WriteString(fmt.Sprintf("%s% -21s: %d (0x%04x)\n", indent, "Length", packet.length, packet.length))
	buffer.WriteString(fmt.Sprintf("%s% -21s: 0x%x\n", indent, "Cookie", packet.cookie))
	buffer.WriteString(fmt.Sprintf("%s% -21s: % x\n", indent, "ID", packet.id[:]))
	buffer.WriteString(fmt.Sprintf("%s% -21s: %d\n", indent, "Number of attributes", packet.NAttributes()))

	for i := 0; i < packet.NAttributes(); i++ {
		attr := packet.Attribute(i)
		attribute_name, ok := attribute_names[attr.Type]
		if !ok {
			attribute_name = "Unknown attribute"
		}
		buffer.WriteString(fmt.Sprintf("%s% -21s: %d (total length %d)\n", indent, "Attribute number", i+1, attr.Length+4))
		buffer.WriteString(fmt.Sprintf("%s% -21s: 0x%04x (%s)\n", indent, "Type", attr.Type, attribute_name))
		buffer.WriteString(fmt.Sprintf("%s% -21s: %d\n", indent, "length", attr.Length))
		buffer.WriteString(fmt.Sprintf("%s% -21s: % x\n", indent, "Value", attr.Value))
		buffer.WriteString(fmt.Sprintf("%s% -21s: %s\n", indent, "Decode", attr.String()))
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
func Bytes2String(p []byte) string {
	var buffer bytes.Buffer
	indent := strings.Repeat(" ", 4)
	length := len(p)
	rest := length % 4
	nb := (length - rest) / 4

	for i := 0; i < nb; i++ {
		buffer.WriteString(fmt.Sprintf("%s%02x %02x %02x %02x\n", indent, p[i*4], p[i*4+1], p[i*4+2], p[i*4+3]))
	}
	if rest > 0 {
		buffer.WriteString(indent)
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
func (packet Packet) MappedAddress() (bool, uint16, string, uint16, error) {
	for i := 0; i < packet.NAttributes(); i++ {
		attr := packet.Attribute(i)
		if ATTRIBUTE_MAPPED_ADDRESS != attr.Type {
			continue
		}
		f, ip, p, err := attr.getAddress()
		return true, f, ip, p, err
	}
	return false, 0, "", 0, nil
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
func (packet Packet) ChangedAddress() (bool, uint16, string, uint16, error) {
	for i := 0; i < packet.NAttributes(); i++ {
		attr := packet.Attribute(i)
		if ATTRIBUTE_CHANGED_ADDRESS != attr.Type {
			continue
		}
		f, ip, p, err := attr.getAddress()
		return true, f, ip, p, err
	}
	return false, 0, "", 0, nil
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
func (packet Packet) XorMappedAddress() (bool, uint16, string, uint16, error) {
	for i := 0; i < packet.NAttributes(); i++ {
		attr := packet.Attribute(i)
		if (ATTRIBUTE_XOR_MAPPED_ADDRESS != attr.Type) && (ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP != attr.Type) {
			continue
		}
		family, ip, port, xip, xport, err := attr.XorMappedAddress()
		_ = ip
		_ = port
		return true, family, xip, xport, err
	}
	return false, 0, "", 0, nil
}
