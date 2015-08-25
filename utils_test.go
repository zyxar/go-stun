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
	"fmt"
	"strings"
	"testing"
)

// See http://www.armware.dk/RFC/rfc/rfc5769.html
func TestCrc32Checksum(t *testing.T) {
	var b []byte = []byte{0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9, 0x00, 0x08, 0x00, 0x14, 0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84, 0xc9, 0x7c, 0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41}
	if 0xc8fb0b4c != crc32Checksum(b) {
		t.Errorf("Invalid fingerptint.")
	}
}

func TestParseIP(t *testing.T) {
	var err error
	var ip string
	ipv4 := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	ipv6 := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

	ip, err = parseIP(ipv4)
	if nil != err {
		t.Errorf(fmt.Sprintf("%s", err))
	}
	if "170.187.204.221" != ip {
		t.Errorf(fmt.Sprintf("Invalid IPV4: given 170.187.204.221, got %s", ip))
	}

	ip, err = parseIP(ipv6)
	if nil != err {
		t.Errorf(fmt.Sprintf("%s", err))
	}
	if "11:2233:4455:6677:8899:AABB:CCDD:EEFF" != strings.ToUpper(ip) {
		t.Errorf(fmt.Sprintf("Invalid IPV6: given 11.2233.4455.6677.8899.AABB.CCDD.EEFF, got %s", ip))
	}

	ipv4 = []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	ip, err = parseIP(ipv4)
	if nil == err {
		t.Errorf(fmt.Sprintf("Test should not succeed."))
	}

	ipv4 = []byte{0xAA, 0xBB, 0xCC}
	ip, err = parseIP(ipv4)
	if nil == err {
		t.Errorf(fmt.Sprintf("Test should not succeed."))
	}

	ipv6 = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	ip, err = parseIP(ipv6)
	if nil == err {
		t.Errorf(fmt.Sprintf("Test should not succeed."))
	}
}

func TestMakeTransportAddress(t *testing.T) {
	var err error
	var transport string

	transport, err = MakeTransportAddress("1.2.3.4", 123)
	if nil != err {
		t.Errorf(fmt.Sprintf("%s", err))
	}
	if "1.2.3.4:123" != transport {
		t.Errorf(fmt.Sprintf("Invalid transport address %s", transport))
	}

	transport, err = MakeTransportAddress("1:2:3:4:5:6:7:8", 123)
	if nil != err {
		t.Errorf(fmt.Sprintf("%s", err))
	}
	if "[1:2:3:4:5:6:7:8]:123" != transport {
		t.Errorf(fmt.Sprintf("Invalid transport address %s", transport))
	}
}
