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
	"hash/crc32"
	"regexp"
	"strconv"
	"strings"
)

// The function calculates the STUN's fingerprint.
// RFC 5389: The value of the attribute is computed as the CRC-32 of the STUN message
//           up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with
//           the 32-bit value 0x5354554e (the XOR helps in cases where an
//           application packet is also using CRC-32 in it).
//
// INPUT
// - p: the list of bytes.
//
// OUTPUT
// - The fingerprint.
//
// NOTE
// Test: http://www.armware.dk/RFC/rfc/rfc5769.html
func crc32Checksum(p []byte) uint32 {
	return crc32.ChecksumIEEE(p) ^ 0x5354554e
}

// This function adds zeros prior to a slice of bytes. The length of the resulting slice is a multiple of 4.
//
// INPUT
// - p: the slice of bytes to padd.
//
// OUTPUT
// - The padded slice.
func padding(p []byte) []byte {
	length := len(p)
	rest := length % 4
	if 0 == rest {
		return p
	}
	b := make([]byte, length+4-rest)
	copy(b, p)
	return b
}

// Given a value, this function calculates the next multiple of 4.
//
// INPUT
// - length: the value.
//
// OUPUT
// - The next multiple of 4.
func nextBoundary(length uint16) uint16 {
	rest := length % 4
	if 0 == rest {
		return length
	}
	return length + 4 - rest
}

// This function extracts the IP address and the port number from a string that represents a transport address.
// The string should be "IP:port".
//
// INPUT
// - in_inet: the transport address.
//            The given transport address could be IPV4 or IPV6.
//            Example for IPV4: "192.168.0.1:1456"
//            Example for IPV6: "[2001:0DB8:0000:85a3:0000:0000:ac1f:8001]:16547"
//
// OUTPUT
// - The IP address.
// - The port number.
// - The error flag.
func InetSplit(in_inet string) (out_ip string, out_port int, out_err error) {
	var err error
	var port int
	var data []string
	var ipv4, ipv6 *regexp.Regexp

	ipv4, err = regexp.Compile("^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d{1,5})$")
	if nil != err {
		panic("Internal error.")
	}

	ipv6, err = regexp.Compile("^\\[([0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})\\]:(\\d{1,5})$")
	if nil != err {
		panic("Internal error.")
	}

	// Is it IPV4 or IPV6?
	data = ipv4.FindStringSubmatch(in_inet)
	if nil == data {
		data = ipv6.FindStringSubmatch(in_inet)
		if nil == data {
			return "", -1, fmt.Errorf("Invalid IP address \"%s\". Can not determine the address' family.", in_inet)
		}
	}

	port, err = strconv.Atoi(data[2])
	if nil != err {
		return "", -1, fmt.Errorf("Invalid INET address \"%s\". The port number is not valid (\"%s\"). It is not an integer.", in_inet, data[2])
	}
	return data[1], port, nil
}

// This function converts an IP address into a list of bytes.
//
// INPUT
// - in_ip: IP address (IPV4 or IPV6).
//          Example for IPV4: "192.168.0.1" will return []byte{12, 13, 14, 15}
//          Example for IPV6: "0011:2233:4455:6677:8899:AABB:CCDD:EEFF" will return []byte{ 0x00, 0x11, 0x22, 0x33, ... }
//
// OUTPUT
// - The list of bytes.
// - The error flag.
func IpToBytes(in_ip string) ([]byte, error) {
	var err error
	var dot, max uint64
	var length int
	var res []byte = make([]byte, 0, 16)
	var data []string

	// Try IPV4.
	data = strings.Split(in_ip, ".")
	if 1 == len(data) { // Try IPV6
		data = strings.Split(in_ip, ":")
	}

	length = len(data)
	if (4 != length) && (8 != length) {
		return nil, fmt.Errorf("Invalid IP address \"%s\".", in_ip)
	}
	if 4 == length {
		max = 255
	} else {
		max = 65535
	}

	for i := 0; i < length; i++ {
		if 4 == length { // IPV4
			dot, err = strconv.ParseUint(data[i], 10, 64)
		} else { // IPV6
			dot, err = strconv.ParseUint(data[i], 16, 64)
		}

		if nil != err {
			return nil, fmt.Errorf("Invalid IP address \"%s\".", in_ip)
		}
		if (dot > max) || (dot < 0) {
			return nil, fmt.Errorf("Invalid IP address \"%s\".", in_ip)
		}
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(dot))

		if 4 == length { // IPV4
			res = append(res, b[1])
		} else { // IPV6
			res = append(res, b...)
		}
	}

	return res, nil
}

// This function converts a list of bytes into a string that represents an IP address.
//
// INPUT
// - b: list of bytes to convert.
//
// OUTPUT
// - The IP address. This can be an IPV4 or IPV6.
// - The error flag.
func BytesToIp(b []byte) (string, error) {
	switch len(b) {
	case 4:
		var ip []string = make([]string, 0, 8)
		for i := range b {
			ip = append(ip, strconv.Itoa(int(b[i])))
		}
		return strings.Join(ip, "."), nil
	case 16:
		var ip []string = make([]string, 0, 8)
		for i := 0; i < 8; i++ {
			ip = append(ip, fmt.Sprintf("%04x", binary.BigEndian.Uint16(b[i*2:(i+1)*2])))
		}
		return strings.Join(ip, ":"), nil
	default:
	}
	return "", errors.New("Invalid list of bytes: this does not represent an IP!")
}

// Given an IP address and a port number, this function creates a transport address.
//
// INPUT
// - in_ip: IP address.
// - in_port: port number.
//
// OUTPUT
// - The transport address.
// - The error flag.
func MakeTransportAddress(in_ip string, in_port int) (string, error) {
	ipv4 := regexp.MustCompile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
	if ipv4.MatchString(in_ip) {
		return fmt.Sprintf("%s:%d", in_ip, in_port), nil
	}
	ipv6 := regexp.MustCompile("^[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}$")
	if ipv6.MatchString(in_ip) {
		return fmt.Sprintf("[%s]:%d", in_ip, in_port), nil
	}
	return "", fmt.Errorf("Invalid IP address \"%s\"!", in_ip)
}
