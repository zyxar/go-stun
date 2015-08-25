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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unicode/utf8"
)

const (
	ATTRIBUTE_FAMILY_IPV4 = 0x01 // IP family is IPV4
	ATTRIBUTE_FAMILY_IPV6 = 0x02 // IP family is IPV6

	/* ------------------------------------------------------------------------------------------------ */
	/* Attributes' types.                                                                               */
	/* See: Session Traversal Utilities for NAT (STUN) Parameters                                       */
	/*      http://www.iana.org/assignments/stun-parameters/stun-parameters.xml                         */
	/* Note: Value ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP is not mentioned in the above document.             */
	/*       But it is used by servers.                                                                 */
	/* ------------------------------------------------------------------------------------------------ */
	ATTRIBUTE_MAPPED_ADDRESS           = 0x0001
	ATTRIBUTE_RESPONSE_ADDRESS         = 0x0002
	ATTRIBUTE_CHANGE_REQUEST           = 0x0003
	ATTRIBUTE_SOURCE_ADDRESS           = 0x0004
	ATTRIBUTE_CHANGED_ADDRESS          = 0x0005
	ATTRIBUTE_USERNAME                 = 0x0006
	ATTRIBUTE_PASSWORD                 = 0x0007
	ATTRIBUTE_MESSAGE_INTEGRITY        = 0x0008
	ATTRIBUTE_ERROR_CODE               = 0x0009
	ATTRIBUTE_UNKNOWN_ATTRIBUTES       = 0x000A
	ATTRIBUTE_REFLECTED_FROM           = 0x000B
	ATTRIBUTE_CHANNEL_NUMBER           = 0x000C
	ATTRIBUTE_LIFETIME                 = 0x000D
	ATTRIBUTE_BANDWIDTH                = 0x0010
	ATTRIBUTE_XOR_PEER_ADDRESS         = 0x0012
	ATTRIBUTE_DATA                     = 0x0013
	ATTRIBUTE_REALM                    = 0x0014
	ATTRIBUTE_NONCE                    = 0x0015
	ATTRIBUTE_XOR_RELAYED_ADDRESS      = 0x0016
	ATTRIBUTE_REQUESTED_ADDRESS_FAMILY = 0x0017
	ATTRIBUTE_EVEN_PORT                = 0x0018
	ATTRIBUTE_REQUESTED_TRANSPORT      = 0x0019
	ATTRIBUTE_DONT_FRAGMENT            = 0x001A
	ATTRIBUTE_XOR_MAPPED_ADDRESS       = 0x0020
	ATTRIBUTE_TIMER_VAL                = 0x0021
	ATTRIBUTE_RESERVATION_TOKEN        = 0x0022
	ATTRIBUTE_PRIORITY                 = 0x0024
	ATTRIBUTE_USE_CANDIDATE            = 0x0025
	ATTRIBUTE_PADDING                  = 0x0026
	ATTRIBUTE_RESPONSE_PORT            = 0x0027
	ATTRIBUTE_CONNECTION_ID            = 0x002A
	ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP   = 0x8020
	ATTRIBUTE_SOFTWARE                 = 0x8022
	ATTRIBUTE_ALTERNATE_SERVER         = 0x8023
	ATTRIBUTE_CACHE_TIMEOUT            = 0x8027
	ATTRIBUTE_FINGERPRINT              = 0x8028
	ATTRIBUTE_ICE_CONTROLLED           = 0x8029
	ATTRIBUTE_ICE_CONTROLLING          = 0x802A
	ATTRIBUTE_RESPONSE_ORIGIN          = 0x802B
	ATTRIBUTE_OTHER_ADDRESS            = 0x802C
	ATTRIBUTE_ECN_CHECK_STUN           = 0x802D
	ATTRIBUTE_CISCO_STUN_FLOWDATA      = 0xC000
)

// This map associates an attribute's value to a attribute's name.
var attribute_names = map[uint16]string{
	ATTRIBUTE_MAPPED_ADDRESS:           "MAPPED_ADDRESS",
	ATTRIBUTE_RESPONSE_ADDRESS:         "RESPONSE_ADDRESS",
	ATTRIBUTE_CHANGE_REQUEST:           "CHANGE_REQUEST",
	ATTRIBUTE_SOURCE_ADDRESS:           "SOURCE_ADDRESS",
	ATTRIBUTE_CHANGED_ADDRESS:          "CHANGED_ADDRESS",
	ATTRIBUTE_USERNAME:                 "USERNAME",
	ATTRIBUTE_PASSWORD:                 "PASSWORD",
	ATTRIBUTE_MESSAGE_INTEGRITY:        "MESSAGE_INTEGRITY",
	ATTRIBUTE_ERROR_CODE:               "ERROR_CODE",
	ATTRIBUTE_UNKNOWN_ATTRIBUTES:       "UNKNOWN_ATTRIBUTES",
	ATTRIBUTE_REFLECTED_FROM:           "REFLECTED_FROM",
	ATTRIBUTE_CHANNEL_NUMBER:           "CHANNEL_NUMBER",
	ATTRIBUTE_LIFETIME:                 "LIFETIME",
	ATTRIBUTE_BANDWIDTH:                "BANDWIDTH",
	ATTRIBUTE_XOR_PEER_ADDRESS:         "XOR_PEER_ADDRESS",
	ATTRIBUTE_DATA:                     "DATA",
	ATTRIBUTE_REALM:                    "REALM",
	ATTRIBUTE_NONCE:                    "NONCE",
	ATTRIBUTE_XOR_RELAYED_ADDRESS:      "XOR_RELAYED_ADDRESS",
	ATTRIBUTE_REQUESTED_ADDRESS_FAMILY: "REQUESTED_ADDRESS_FAMILY",
	ATTRIBUTE_EVEN_PORT:                "EVEN_PORT",
	ATTRIBUTE_REQUESTED_TRANSPORT:      "REQUESTED_TRANSPORT",
	ATTRIBUTE_DONT_FRAGMENT:            "DONT_FRAGMENT",
	ATTRIBUTE_XOR_MAPPED_ADDRESS:       "XOR_MAPPED_ADDRESS",
	ATTRIBUTE_TIMER_VAL:                "TIMER_VAL",
	ATTRIBUTE_RESERVATION_TOKEN:        "RESERVATION_TOKEN",
	ATTRIBUTE_PRIORITY:                 "PRIORITY",
	ATTRIBUTE_USE_CANDIDATE:            "USE_CANDIDATE",
	ATTRIBUTE_PADDING:                  "PADDING",
	ATTRIBUTE_RESPONSE_PORT:            "RESPONSE_PORT",
	ATTRIBUTE_CONNECTION_ID:            "CONNECTION_ID",
	ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP:   "XOR_MAPPED_ADDRESS",
	ATTRIBUTE_SOFTWARE:                 "SOFTWARE",
	ATTRIBUTE_ALTERNATE_SERVER:         "ALTERNATE_SERVER",
	ATTRIBUTE_CACHE_TIMEOUT:            "CACHE_TIMEOUT",
	ATTRIBUTE_FINGERPRINT:              "FINGERPRINT",
	ATTRIBUTE_ICE_CONTROLLED:           "ICE_CONTROLLED",
	ATTRIBUTE_ICE_CONTROLLING:          "ICE_CONTROLLING",
	ATTRIBUTE_RESPONSE_ORIGIN:          "RESPONSE_ORIGIN",
	ATTRIBUTE_OTHER_ADDRESS:            "OTHER_ADDRESS",
	ATTRIBUTE_ECN_CHECK_STUN:           "ECN_CHECK_STUN",
	ATTRIBUTE_CISCO_STUN_FLOWDATA:      "CISCO_STUN_FLOWDATA",
}

// This structure represents a message's attribute of a STUN message.
// RFC 5389: The value in the length field MUST contain the length of the Value
//           part of the attribute, prior to padding, measured in bytes.  Since
//           STUN aligns attributes on 32-bit boundaries, attributes whose content
//           is not a multiple of 4 bytes are padded with 1, 2, or 3 bytes of
//           padding so that its value contains a multiple of 4 bytes.  The
//           padding bits are ignored, and may be any value.
//
// **BUT** RFC 5389 says that the **real** length must be a multiple of 4! (no padding)
type Attribute struct {
	Type   uint16 // The attribute's type (constant ATTRIBUTE_...), 16 bits
	Length uint16 // The length of the attribute, 16 bits
	Value  []byte // The attribute's value.
}

/* ------------------------------------------------------------------------------------------------ */
/* Create                                                                                           */
/*                                                                                                  */
/* NOTE: http://code.google.com/p/go-idn/                                                           */
/* ------------------------------------------------------------------------------------------------ */

// Create a message's attribute.
//
// INPUT
// - _type: attribute's type.
// - value: attribute's value.
//
// OUTPUT
// - The new attribute.
// - The error flag.
func makeAttribute(_type uint16, value []byte) (attr Attribute, err error) {
	if (0 != len(value)%4) && (rfc == RFC3489) {
		err = errors.New("STUN is configured to be compliant with RFC 3489! Value's length must be a multiple of 4 bytes!")
		return
	} else if len(value) > 65535 {
		err = fmt.Errorf("Can not create new attribute: attribute's value is too long (%d bytes)", len(value))
		return
	}

	b := padding(value)
	leng := len(b)
	attr.Type = _type
	attr.Value = make([]byte, leng)
	attr.Length = uint16(len(value))
	copy(attr.Value, b)
	return attr, nil
}

// Given an attribute that represents a "XOR mapped" address, this function returns the transport address.
// See http://www.nexcom.fr/2012/06/stun-la-base/
//
// OUTPUT
// - The address' family (1 for IPV4 or 2 for IPV6).
// - The IP address.
//   + Example for IPV4: "192.168.0.1"
//   + Example for IPV6: "0011:2233:4455:6677:8899:AABB:CCDD:EEFF"
// - The port number.
// - The XORED IP address (should be equal to the mapped address).
// - The XORED port (should be equal to the mapped port).
// - The error flag.
func (attr Attribute) XorMappedAddress() (family uint16, addr net.IP, port uint16, addr_xor net.IP, port_xor uint16, err error) {
	cookie := []byte{0x21, 0x12, 0xA4, 0x42} // 0x2112A442
	xored_ip := make([]byte, 0, 16)

	family = binary.BigEndian.Uint16(attr.Value[0:2])
	if (ATTRIBUTE_FAMILY_IPV4 != family) && (ATTRIBUTE_FAMILY_IPV6 != family) {
		err = fmt.Errorf("Invalid address' family: 0x%02x", family)
		return
	}
	port = binary.BigEndian.Uint16(attr.Value[2:4])
	addr = parseIP(attr.Value[4:])
	if ATTRIBUTE_FAMILY_IPV4 == family { // IPV4
		if len(attr.Value[4:]) != 4 {
			err = fmt.Errorf("Invalid IPV4 address: % x", attr.Value[4:])
			return
		}
		for i := 0; i < 4; i++ {
			xored_ip = append(xored_ip, attr.Value[i+4]^cookie[i])
		}
	} else { // IPV6
		if len(attr.Value[4:]) != 16 {
			err = fmt.Errorf("Invalid IPV6 address: % x", attr.Value[4:])
			return
		}
		for i := 0; i < 16; i++ {
			xored_ip = append(xored_ip, attr.Value[i+4]^cookie[i])
		}
	}
	addr_xor = parseIP(xored_ip)
	port_xor = port ^ 0x2112
	return
}

// Given an attribute that represents a "SOFTWARE" attribute, this function returns the name of the software.
//
// OUTPUT
// - The name of the software.
func (attr Attribute) Software() string {
	for i := 0; i < len(attr.Value); {
		r, size := utf8.DecodeRune(attr.Value[i:])
		if utf8.RuneError == r {
			return "Can not convert this list of bytes into a string. It is not UTF8 encoded."
		}
		i += size
	}
	return string(attr.Value)
}

// This function returns a 32-bit integer that represents the fingerprint.
//
// OUTPUT
// - The fingerprint.
// - The error flag.
func (attr Attribute) Fingerprint() (crc uint32, err error) {
	if 4 != len(attr.Value) {
		err = fmt.Errorf("Invalid fingerprint (% x)", attr.Value)
		return
	}
	crc = binary.BigEndian.Uint32(attr.Value)
	return
}

// This function returns the value of an attribute which type is "REQUEST_CHANGE".
//
// OUPUT
// - A boolean value that indicates whether IP change is requested or not.
// - A boolean value that indicates whether port number change is requested or not.
// - The error flag.
func (attr Attribute) ChangeRequest() (bool, bool, error) {
	if 4 != len(attr.Value) {
		return false, false, fmt.Errorf("Invalid change requested value (% x)", attr.Value)
	}
	return (0x04 | attr.Value[3]) != 0, (0x02 | attr.Value[3]) != 0, nil
}

/* ------------------------------------------------------------------------------------------------ */
/* Export                                                                                           */
/* ------------------------------------------------------------------------------------------------ */

// This function returns a textual representation of the attribute, if possible; otherwise null string.
func (attr Attribute) String() string {
	switch attr.Type {
	case ATTRIBUTE_MAPPED_ADDRESS, ATTRIBUTE_SOURCE_ADDRESS, ATTRIBUTE_CHANGED_ADDRESS:
		_, ip, port := attr.decode()
		addr := net.UDPAddr{IP: ip, Port: int(port)}
		return addr.String()
	case ATTRIBUTE_XOR_MAPPED_ADDRESS, ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP:
		_, ip, port, xored_ip, xored_port, err := attr.XorMappedAddress()
		if nil != err {
			return ""
		}
		addr := net.UDPAddr{IP: ip, Port: int(port)}
		addr_xor := net.UDPAddr{IP: xored_ip, Port: int(xored_port)}
		return fmt.Sprintf("%s => %s", addr.String(), addr_xor.String())
	case ATTRIBUTE_SOFTWARE:
		return attr.Software()
	case ATTRIBUTE_FINGERPRINT:
		if crc, err := attr.Fingerprint(); nil != err {
			return ""
		} else {
			return fmt.Sprintf("0x%08x", crc)
		}
	case ATTRIBUTE_CHANGE_REQUEST:
		ip, port, err := attr.ChangeRequest()
		if nil != err {
			return ""
		}
		return fmt.Sprintf("Change IP: %v Change port: %v", ip, port)
	default:
	}
	return ""
}

// Given an attribute that represents an address, this function returns the transport address (IP and port number).
//
// OUTPUT
// - The address' family (1 for IPV4 or 2 for IPV6).
// - The IP address.
//   + Example for IPV4: "192.168.0.1"
//   + Example for IPV6: "0011:2233:4455:6677:8899:AABB:CCDD:EEFF"
// - The port number.
func (attr *Attribute) decode() (uint16, net.IP, uint16) {
	return binary.BigEndian.Uint16(attr.Value[0:2]), parseIP(attr.Value[4:]), binary.BigEndian.Uint16(attr.Value[2:4])
}
