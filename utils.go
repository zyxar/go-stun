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
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"regexp"
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

// This function converts a list of bytes into a string that represents an IP address.
//
// INPUT
// - b: list of bytes to convert.
//
// OUTPUT
// - The IP address. This can be an IPV4 or IPV6.
// - The error flag.
func parseIP(b []byte) (string, error) {
	if len(b) != 4 && len(b) != 16 {
		return "", errors.New("Invalid list of bytes: this does not represent an IP!")
	}
	return net.IP(b).String(), nil
}

// Given an IP address and a port number, this function creates a transport address.
//
// INPUT
// - ip: IP address.
// - port: port number.
//
// OUTPUT
// - The transport address.
// - The error flag.
func MakeTransportAddress(ip string, port int) (string, error) {
	ipv4 := regexp.MustCompile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
	if ipv4.MatchString(ip) {
		return fmt.Sprintf("%s:%d", ip, port), nil
	}
	ipv6 := regexp.MustCompile("^[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}$")
	if ipv6.MatchString(ip) {
		return fmt.Sprintf("[%s]:%d", ip, port), nil
	}
	return "", fmt.Errorf("Invalid IP address \"%s\"!", ip)
}
