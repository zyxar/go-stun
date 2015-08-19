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
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	// STUN's magic cookie.
	STUN_MAGIC_COOKIE = 0x2112A442

	/* ------------------------------------------------------------------------------------------------ */
	/* Packet' types.                                                                                   */
	/* See: Session Traversal Utilities for NAT (STUN) Parameters                                       */
	/*      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml                         */
	/* ------------------------------------------------------------------------------------------------ */
	STUN_TYPE_BINDING_REQUEST                   = 0x0001
	STUN_TYPE_BINDING_RESPONSE                  = 0x0101
	STUN_TYPE_BINDING_ERROR_RESPONSE            = 0x0111
	STUN_TYPE_SHARED_SECRET_REQUEST             = 0x0002
	STUN_TYPE_SHARED_SECRET_RESPONSE            = 0x0102
	STUN_TYPE_SHARED_ERROR_RESPONSE             = 0x0112
	STUN_TYPE_ALLOCATE                          = 0x0003
	STUN_TYPE_ALLOCATE_RESPONSE                 = 0x0103
	STUN_TYPE_ALLOCATE_ERROR_RESPONSE           = 0x0113
	STUN_TYPE_REFRESH                           = 0x0004
	STUN_TYPE_REFRESH_RESPONSE                  = 0x0104
	STUN_TYPE_REFRESH_ERROR_RESPONSE            = 0x0114
	STUN_TYPE_SEND                              = 0x0006
	STUN_TYPE_SEND_RESPONSE                     = 0x0106
	STUN_TYPE_SEND_ERROR_RESPONSE               = 0x0116
	STUN_TYPE_DATA                              = 0x0007
	STUN_TYPE_DATA_RESPONSE                     = 0x0107
	STUN_TYPE_DATA_ERROR_RESPONSE               = 0x0117
	STUN_TYPE_CREATE_PERMISIION                 = 0x0008
	STUN_TYPE_CREATE_PERMISIION_RESPONSE        = 0x0108
	STUN_TYPE_CREATE_PERMISIION_ERROR_RESPONSE  = 0x0118
	STUN_TYPE_CHANNEL_BINDING                   = 0x0009
	STUN_TYPE_CHANNEL_BINDING_RESPONSE          = 0x0109
	STUN_TYPE_CHANNEL_BINDING_ERROR_RESPONSE    = 0x0119
	STUN_TYPE_CONNECT                           = 0x000A
	STUN_TYPE_CONNECT_RESPONSE                  = 0x010A
	STUN_TYPE_CONNECT_ERROR_RESPONSE            = 0x011A
	STUN_TYPE_CONNECTION_BIND                   = 0x000B
	STUN_TYPE_CONNECTION_BIND_RESPONSE          = 0x010B
	STUN_TYPE_CONNECTION_BIND_ERROR_RESPONSE    = 0x011B
	STUN_TYPE_CONNECTION_ATTEMPT                = 0x000C
	STUN_TYPE_CONNECTION_ATTEMPT_RESPONSE       = 0x010C
	STUN_TYPE_CONNECTION_ATTEMPT_ERROR_RESPONSE = 0x011C

	/* ------------------------------------------------------------------------------------------------ */
	/* Error values.                                                                                    */
	/* See: Session Traversal Utilities for NAT (STUN) Parameters                                       */
	/*      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml                         */
	/* ------------------------------------------------------------------------------------------------ */
	STUN_ERROR_TRY_ALTERNATE                  = 300
	STUN_ERROR_BAD_REQUEST                    = 400
	STUN_ERROR_UNAUTHORIZED                   = 401
	STUN_ERROR_UNASSIGNED_402                 = 402
	STUN_ERROR_FORBIDDEN                      = 403
	STUN_ERROR_UNKNOWN_ATTRIBUTE              = 420
	STUN_ERROR_ALLOCATION_MISMATCH            = 437
	STUN_ERROR_STALE_NONCE                    = 438
	STUN_ERROR_UNASSIGNED_439                 = 439
	STUN_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED   = 440
	STUN_ERROR_WRONG_CREDENTIALS              = 441
	STUN_ERROR_UNSUPPORTED_TRANSPORT_PROTOCOL = 442
	STUN_ERROR_PEER_ADDRESS_FAMILY_MISMATCH   = 443
	STUN_ERROR_CONNECTION_ALREADY_EXISTS      = 446
	STUN_ERROR_CONNECTION_TIMEOUT_OR_FAILURE  = 447
	STUN_ERROR_ALLOCATION_QUOTA_REACHED       = 486
	STUN_ERROR_ROLE_CONFLICT                  = 487
	STUN_ERROR_SERVER_ERROR                   = 500
	STUN_ERROR_INSUFFICIENT_CAPACITY          = 508
)

// This map associates an type's value to a type's name.
var message_types = map[uint16]string{
	STUN_TYPE_BINDING_REQUEST:                   "BINDING_REQUEST",
	STUN_TYPE_BINDING_RESPONSE:                  "BINDING_RESPONSE",
	STUN_TYPE_BINDING_ERROR_RESPONSE:            "BINDING_ERROR_RESPONSE",
	STUN_TYPE_SHARED_SECRET_REQUEST:             "SHARED_SECRET_REQUEST",
	STUN_TYPE_SHARED_SECRET_RESPONSE:            "SHARED_SECRET_RESPONSE",
	STUN_TYPE_SHARED_ERROR_RESPONSE:             "SHARED_ERROR_RESPONSE",
	STUN_TYPE_ALLOCATE:                          "ALLOCATE",
	STUN_TYPE_ALLOCATE_RESPONSE:                 "ALLOCATE_RESPONSE",
	STUN_TYPE_ALLOCATE_ERROR_RESPONSE:           "ALLOCATE_ERROR_RESPONSE",
	STUN_TYPE_REFRESH:                           "REFRESH",
	STUN_TYPE_REFRESH_RESPONSE:                  "REFRESH_RESPONSE",
	STUN_TYPE_REFRESH_ERROR_RESPONSE:            "REFRESH_ERROR_RESPONSE",
	STUN_TYPE_SEND:                              "SEND",
	STUN_TYPE_SEND_RESPONSE:                     "SEND_RESPONSE",
	STUN_TYPE_SEND_ERROR_RESPONSE:               "SEND_ERROR_RESPONSE",
	STUN_TYPE_DATA:                              "DATA",
	STUN_TYPE_DATA_RESPONSE:                     "DATA_RESPONSE",
	STUN_TYPE_DATA_ERROR_RESPONSE:               "DATA_ERROR_RESPONSE",
	STUN_TYPE_CREATE_PERMISIION:                 "CREATE_PERMISIION",
	STUN_TYPE_CREATE_PERMISIION_RESPONSE:        "CREATE_PERMISIION_RESPONSE",
	STUN_TYPE_CREATE_PERMISIION_ERROR_RESPONSE:  "CREATE_PERMISIION_ERROR_RESPONSE",
	STUN_TYPE_CHANNEL_BINDING:                   "CHANNEL_BINDING",
	STUN_TYPE_CHANNEL_BINDING_RESPONSE:          "CHANNEL_BINDING_RESPONSE",
	STUN_TYPE_CHANNEL_BINDING_ERROR_RESPONSE:    "CHANNEL_BINDING_ERROR_RESPONSE",
	STUN_TYPE_CONNECT:                           "CONNECT",
	STUN_TYPE_CONNECT_RESPONSE:                  "CONNECT_RESPONSE",
	STUN_TYPE_CONNECT_ERROR_RESPONSE:            "CONNECT_ERROR_RESPONSE",
	STUN_TYPE_CONNECTION_BIND:                   "CONNECTION_BIND",
	STUN_TYPE_CONNECTION_BIND_RESPONSE:          "CONNECTION_BIND_RESPONSE",
	STUN_TYPE_CONNECTION_BIND_ERROR_RESPONSE:    "CONNECTION_BIND_ERROR_RESPONSE",
	STUN_TYPE_CONNECTION_ATTEMPT:                "CONNECTION_ATTEMPT",
	STUN_TYPE_CONNECTION_ATTEMPT_RESPONSE:       "CONNECTION_ATTEMPT_RESPONSE",
	STUN_TYPE_CONNECTION_ATTEMPT_ERROR_RESPONSE: "CONNECTION_ATTEMPT_ERROR_RESPONSE",
}

// This map associates an error's code with an error's name.
var error_names = map[uint16]string{
	STUN_ERROR_TRY_ALTERNATE:                  "TRY_ALTERNATE",
	STUN_ERROR_BAD_REQUEST:                    "BAD_REQUEST",
	STUN_ERROR_UNAUTHORIZED:                   "UNAUTHORIZED",
	STUN_ERROR_UNASSIGNED_402:                 "UNASSIGNED_402",
	STUN_ERROR_FORBIDDEN:                      "FORBIDDEN",
	STUN_ERROR_UNKNOWN_ATTRIBUTE:              "UNKNOWN_ATTRIBUTE",
	STUN_ERROR_ALLOCATION_MISMATCH:            "ALLOCATION_MISMATCH",
	STUN_ERROR_STALE_NONCE:                    "STALE_NONCE",
	STUN_ERROR_UNASSIGNED_439:                 "UNASSIGNED_439",
	STUN_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED:   "ADDRESS_FAMILY_NOT_SUPPORTED",
	STUN_ERROR_WRONG_CREDENTIALS:              "WRONG_CREDENTIALS",
	STUN_ERROR_UNSUPPORTED_TRANSPORT_PROTOCOL: "UNSUPPORTED_TRANSPORT_PROTOCOL",
	STUN_ERROR_PEER_ADDRESS_FAMILY_MISMATCH:   "PEER_ADDRESS_FAMILY_MISMATCH",
	STUN_ERROR_CONNECTION_ALREADY_EXISTS:      "CONNECTION_ALREADY_EXISTS",
	STUN_ERROR_CONNECTION_TIMEOUT_OR_FAILURE:  "CONNECTION_TIMEOUT_OR_FAILURE",
	STUN_ERROR_ALLOCATION_QUOTA_REACHED:       "ALLOCATION_QUOTA_REACHED",
	STUN_ERROR_ROLE_CONFLICT:                  "ROLE_CONFLICT",
	STUN_ERROR_SERVER_ERROR:                   "SERVER_ERROR",
	STUN_ERROR_INSUFFICIENT_CAPACITY:          "INSUFFICIENT_CAPACITY",
}

/* ------------------------------------------------------------------------------------------------ */
/* Types.                                                                                           */
/* ------------------------------------------------------------------------------------------------ */

// This type represents a STUN UDP packet.
type Packet struct {
	// Type of the packet (constant STUN_TYPE_...).
	stype uint16
	// RFC5389: The message length MUST contain the size, in bytes, of the message
	//           **not** including the 20-byte STUN header.  Since all STUN attributes are
	//           padded to a multiple of 4 bytes, the last 2 bits of this field are
	//           always zero.  This provides another way to distinguish STUN packets
	//           from packets of other protocols.
	length     uint16          // Lentgth of the packet. 16 bits
	cookie     uint32          // The magik cookie (32 bits)
	id         [12]byte        // The STUN's ID. 96 bits (12 bytes)
	attributes []StunAttribute // The list of attributes included in the packet.
}

/* ------------------------------------------------------------------------------------------------ */
/* API                                                                                              */
/* ------------------------------------------------------------------------------------------------ */

// Set the packet's type.
//
// INPUT
// - in_type: the packet's type.
func (v *Packet) SetType(in_type uint16) {
	v.stype = in_type
}

// Get the packet's type.
//
// OUTPUT
// - The packet's type.
func (v *Packet) GetType() uint16 {
	return v.stype
}

// Set the packet's length.
//
// INPUT
// - in_length; the packet's length.
func (v *Packet) SetLength(in_length uint16) {
	v.length = in_length
}

// Set the packet's length.
//
// OUTPUT
// - The packet's length.
func (v *Packet) GetLength() uint16 {
	return v.length
}

// Set the STUN's ID.
//
// INPUT
// - in_id: the STUN's ID.
func (v *Packet) SetId(in_id []byte) {
	if 12 != len(in_id) {
		panic("Internal Error: invalid STUN ID.")
	}
	copy(v.id[:], in_id)
}

// Get the STUN's ID.
//
// OUTPUT
// - The STUN's ID.
func (v *Packet) GetId() []byte {
	return v.id[:]
}

// Set the packet's magic cookie.
//
// INPUT
// - in_cookie: the magic cookie.
func (v *Packet) SetCookie(in_cookie uint32) {
	v.cookie = in_cookie
}

// Get the packet's magic cookie.
//
// OUTPUT
// - The packet's magic cookie.
func (v *Packet) GetCookie() uint32 {
	return v.cookie
}

// Add an attribute to the packet.
//
// INPUT
// - a: the attribute to add
func (v *Packet) AddAttribute(a StunAttribute) {
	v.attributes = append(v.attributes, a)
	// Add the *TOTAL* length of the added attribute.
	// (Padded) value + header

	if STUN_RFC_3489 == rfc {
		v.length += a.Length + 4
		if 0 != v.length%4 {
			panic("STUN is configured to be compliant with RFC 3489. All attributes' lengths must be multiples of 4.")
		}
	} else {
		v.length += __nextBoundary(a.Length) + 4
	}

}

// Return the number of attributes in the packet.
//
// OUTPUT
// - The number of attributes in the packet.
func (v *Packet) GetAttributesCount() int {
	return len(v.attributes)
}

// Get a an attribute from the packet.
//
// INPUT
// - in_index: index of the attribute within the packet.
//
// OUTPUT
// - The attribute.
func (v *Packet) GetAttribute(in_index int) StunAttribute {
	return v.attributes[in_index]
}

// This function creates a sequence of bytes from a STUN packet, that can be sent to the network.
//
// OUTPUT
// - The sequence of bytes.
func (v *Packet) Bytes() []byte {
	length := 20
	for i := 0; i < len(v.attributes); i++ {
		length += 4 + len(v.attributes[i].Value)
	}
	if length > 65535 {
		return nil
	}
	p := make([]byte, length)
	// Convert the header
	binary.BigEndian.PutUint16(p[0:2], v.stype)  // Add the message's type.
	binary.BigEndian.PutUint16(p[2:4], v.length) // Add the packet's length. // Note: at this point, set the length to 0.
	binary.BigEndian.PutUint32(p[4:8], v.cookie) // Add the magic cookie.
	copy(p[8:], v.id[:])                         // Add the transaction ID.
	pos := 20
	for i := 0; i < len(v.attributes); i++ { // Add attributes.
		binary.BigEndian.PutUint16(p[pos:pos+2], v.attributes[i].Type)
		pos += 2
		binary.BigEndian.PutUint16(p[pos:pos+2], v.attributes[i].Length) // We set the *real* length, not the padded one.
		pos += 2
		copy(p[pos:], v.attributes[i].Value) // Please keep in mind that values contain padding.
		pos += len(v.attributes[i].Value)
	}
	// var length uint16 = uint16(len(p) - 20)
	binary.BigEndian.PutUint16(p[2:4], v.length)
	return p
}

// This function converts a sequence of bytes into a STUN packet.
//
// INPUT
// - b: the sequence of bytes. if b == nil, it creates an empty packet.
//
// OUTPUT
// - The STUN packet.
// - The error flag.
//
// NOTE
// The length of the packet is initialized to the value 20, which is the length of the header.
func MakePacket(b []byte) (Packet, error) {
	pkt := Packet{
		cookie:     STUN_MAGIC_COOKIE,
		length:     0, // Header (20 bytes) is **not** included.
		attributes: make([]StunAttribute, 0, 10),
	}
	if b == nil {
		return pkt, nil
	}
	var err error
	b_len := len(b)
	if b_len < 20 {
		return pkt, fmt.Errorf("The given list of bytes does not represent a STUN packet. Only %d bytes.", b_len)
	}
	if b_len > 65535 {
		return pkt, fmt.Errorf("The given list of bytes does not represent a STUN packet. %d bytes.", b_len)
	}

	pkt.stype = binary.BigEndian.Uint16(b[0:2])
	pkt.length = binary.BigEndian.Uint16(b[2:4])
	// if (STUN_MAGIC_COOKIE != cookie) { return pkt, fmt.Errorf("The value of the magic cookie is not correct (%d).", cookie) }
	pkt.cookie = binary.BigEndian.Uint32(b[4:8])
	pkt.SetId(b[8:20])

	// Get attributes
	// For RFC 5389 only:
	//     Please keep in mind that values contain padding.
	//     Lengthes of attribltes' values don't include the padding's length.
	var pos uint16 = 20
	for pos < uint16(b_len) {
		var vtype uint16
		var length uint16
		var value []byte
		var attribute StunAttribute

		vtype = binary.BigEndian.Uint16(b[pos : pos+2])    // Type of the attribute.
		length = binary.BigEndian.Uint16(b[pos+2 : pos+4]) // Length of the attribute (without the padding !!!!!!)
		value = b[pos+4 : pos+4+length]                    // The value.
		attribute, err = AttributeCreate(vtype, value, &pkt)
		if nil != err {
			return pkt, err
		}
		pkt.AddAttribute(attribute)

		// 4 bytes: for the attribute's header.
		if STUN_RFC_3489 == rfc {
			pos += 4 + length
			if 0 != pos%4 {
				return pkt, fmt.Errorf("STUN is configured to be compliant with RFC 3489! Value's length must be a multiple of 4 bytes!")
			}
		} else {
			// RFC 5389 only: we must take care of the padding.
			pos += 4 + __nextBoundary(length)
		}
	}

	return pkt, nil
}

// This function generates a textual representation of a given STUN packet.
//
// OUTPUT
// - The textual representation.
func (v *Packet) String(in_indent int) string {
	indent := strings.Repeat(" ", in_indent)
	lines := make([]string, 0, 10)
	var mt string
	var ok bool

	mt, ok = message_types[v.GetType()]
	if !ok {
		mt = "Unknown message type"
	}

	lines = append(lines, fmt.Sprintf("%s% -21s: 0x%04x (%s)", indent, "Type", v.GetType(), mt))
	lines = append(lines, fmt.Sprintf("%s% -21s: %d (0x%04x)", indent, "Length", v.GetLength(), v.GetLength()))
	lines = append(lines, fmt.Sprintf("%s% -21s: 0x%x", indent, "Cookie", v.GetCookie()))
	lines = append(lines, fmt.Sprintf("%s% -21s: % x", indent, "ID", v.GetId()))
	lines = append(lines, fmt.Sprintf("%s% -21s: %d", indent, "Number of attributes", v.GetAttributesCount()))

	for i := 0; i < v.GetAttributesCount(); i++ {
		var ok bool
		var attribute_name, attribute_string string

		a := v.GetAttribute(i)
		attribute_name, ok = attribute_names[a.Type]
		if !ok {
			attribute_name = "Unknown attribute"
		}
		attribute_string, ok = a.String()

		lines = append(lines, fmt.Sprintf("%s% -21s: %d (total length %d)", indent, "Attribute number", i+1, a.Length+4))
		lines = append(lines, fmt.Sprintf("%s% -21s: 0x%04x (%s)", indent, "Type", a.Type, attribute_name))
		lines = append(lines, fmt.Sprintf("%s% -21s: %d", indent, "length", a.Length))
		lines = append(lines, fmt.Sprintf("%s% -21s: % x", indent, "Value", a.Value))
		lines = append(lines, fmt.Sprintf("%s% -21s: %s", indent, "Decode", attribute_string))
	}

	return strings.Join(lines, "\n")
}

// This function generates a nicely formatted representation of a list of bytes received from the network.
//
// INPUT
// - in_bytes: the list of bytes extracted from the network.
// - in_indent: The parameter defines the number of spaces in front of each line of the returned text.
//
// OUPUT
// - The nicely formatted representation if the given list of bytes.
func Bytes2String(in_bytes []byte, in_indent int) string {
	indent := strings.Repeat(" ", in_indent)
	length := len(in_bytes)
	rest := length % 4
	nb := (length - rest) / 4
	text := make([]string, 0, 10)

	for i := 0; i < nb; i++ {
		b1 := in_bytes[i*4]
		b2 := in_bytes[i*4+1]
		b3 := in_bytes[i*4+2]
		b4 := in_bytes[i*4+3]
		text = append(text, fmt.Sprintf("%s%02x %02x %02x %02x", indent, b1, b2, b3, b4))
	}
	if rest > 0 {
		tokens := make([]string, 0, 4)

		for i := 0; i < 4; i++ {
			if nb*4+i >= len(in_bytes) {
				tokens = append(tokens, " ")
			} else {
				tokens = append(tokens, fmt.Sprintf("%02x", in_bytes[nb*4+i]))
			}
		}
		text = append(text, fmt.Sprintf("%s %s %s %s", indent, tokens[0], tokens[1], tokens[2], tokens[3]))
	}

	return strings.Join(text, "\n")
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
func (v *Packet) GetMappedAddress() (bool, uint16, string, uint16, error) {
	for i := 0; i < v.GetAttributesCount(); i++ {
		a := v.GetAttribute(i)
		if STUN_ATTRIBUT_MAPPED_ADDRESS != a.Type {
			continue
		}
		f, ip, p, err := a.__getAddress()
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
func (v *Packet) GetChangedAddress() (bool, uint16, string, uint16, error) {
	for i := 0; i < v.GetAttributesCount(); i++ {
		a := v.GetAttribute(i)
		if STUN_ATTRIBUT_CHANGED_ADDRESS != a.Type {
			continue
		}
		f, ip, p, err := a.__getAddress()
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
func (v *Packet) GetXorMappedAddress() (bool, uint16, string, uint16, error) {
	for i := 0; i < v.GetAttributesCount(); i++ {
		a := v.GetAttribute(i)
		if (STUN_ATTRIBUT_XOR_MAPPED_ADDRESS != a.Type) && (STUN_ATTRIBUT_XOR_MAPPED_ADDRESS_EXP != a.Type) {
			continue
		}

		family, ip, port, xip, xport, err := a.AttributeGetXorMappedAddress()
		_ = ip
		_ = port
		return true, family, xip, xport, err
	}
	return false, 0, "", 0, nil
}
