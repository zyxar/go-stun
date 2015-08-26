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
	// "bytes"
	"bytes"
	"testing"
)

func TestAttrType(t *testing.T) {
	{
		var attr mappedAddressAttribute
		if attr.Type() != ATTRIBUTE_MAPPED_ADDRESS {
			t.Error("attr type error")
		}
	}
	{
		var attr sourceAddressAttribute
		if attr.Type() != ATTRIBUTE_SOURCE_ADDRESS {
			t.Error("attr type error")
		}
	}
	{
		var attr changedAddressAttribute
		if attr.Type() != ATTRIBUTE_CHANGED_ADDRESS {
			t.Error("attr type error")
		}
	}
	{
		var attr xorMappedAddressAttribute
		if attr.Type() != ATTRIBUTE_XOR_MAPPED_ADDRESS {
			t.Error("attr type error")
		}
	}
	{
		var attr xorMappedAddressExpAttribute
		if attr.Type() != ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP {
			t.Error("attr type error")
		}
	}
	{
		var attr softwareAttribute
		if attr.Type() != ATTRIBUTE_SOFTWARE {
			t.Error("attr type error")
		}
	}
	{
		var attr fingerprintAttribute
		if attr.Type() != ATTRIBUTE_FINGERPRINT {
			t.Error("attr type error")
		}
	}
	{
		var attr changeRequestAttribute
		if attr.Type() != ATTRIBUTE_CHANGE_REQUEST {
			t.Error("attr type error")
		}
	}
}

func TestParseAttributes(t *testing.T) {
	shouldNotPass := "should not pass"
	var err error
	b := []byte{0x00, 0x01, 0xdd, 0xbf, 0x7f, 0x00, 0x00, 0x01}
	c := []byte{0, 0, 0, 0}

	if _, err = parseAttribute(0xFFFF, nil); err == nil {
		t.Error(shouldNotPass)
	}

	if _, err = parseAttribute(ATTRIBUTE_MAPPED_ADDRESS, b); err != nil {
		t.Error(err)
	}
	if _, err = parseAttribute(ATTRIBUTE_MAPPED_ADDRESS, nil); err == nil {
		t.Error(shouldNotPass)
	}
	if _, err = parseAttribute(ATTRIBUTE_MAPPED_ADDRESS, c); err == nil {
		t.Error(shouldNotPass)
	}

	if _, err = parseAttribute(ATTRIBUTE_SOURCE_ADDRESS, b); err != nil {
		t.Error(err)
	}
	if _, err = parseAttribute(ATTRIBUTE_SOURCE_ADDRESS, nil); err == nil {
		t.Error(shouldNotPass)
	}
	if _, err = parseAttribute(ATTRIBUTE_SOURCE_ADDRESS, c); err == nil {
		t.Error(shouldNotPass)
	}

	if _, err = parseAttribute(ATTRIBUTE_CHANGED_ADDRESS, b); err != nil {
		t.Error(err)
	}
	if _, err = parseAttribute(ATTRIBUTE_CHANGED_ADDRESS, nil); err == nil {
		t.Error(shouldNotPass)
	}
	if _, err = parseAttribute(ATTRIBUTE_CHANGED_ADDRESS, c); err == nil {
		t.Error(shouldNotPass)
	}

	if _, err = parseAttribute(ATTRIBUTE_XOR_MAPPED_ADDRESS, b); err != nil {
		t.Error(err)
	}
	if _, err = parseAttribute(ATTRIBUTE_XOR_MAPPED_ADDRESS, nil); err == nil {
		t.Error(shouldNotPass)
	}
	if _, err = parseAttribute(ATTRIBUTE_XOR_MAPPED_ADDRESS, c); err == nil {
		t.Error(shouldNotPass)
	}

	if _, err = parseAttribute(ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP, b); err != nil {
		t.Error(err)
	}
	if _, err = parseAttribute(ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP, nil); err == nil {
		t.Error(shouldNotPass)
	}
	if _, err = parseAttribute(ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP, c); err == nil {
		t.Error(shouldNotPass)
	}

	if _, err = parseAttribute(ATTRIBUTE_SOFTWARE, nil); err != nil {
		t.Error(err)
	}

	if _, err = parseAttribute(ATTRIBUTE_FINGERPRINT, c); err != nil {
		t.Error(err)
	}
	if _, err = parseAttribute(ATTRIBUTE_FINGERPRINT, nil); err == nil {
		t.Error(shouldNotPass)
	}
	if _, err = parseAttribute(ATTRIBUTE_FINGERPRINT, b); err == nil {
		t.Error(shouldNotPass)
	}

	if _, err = parseAttribute(ATTRIBUTE_CHANGE_REQUEST, c); err != nil {
		t.Error(err)
	}
	if _, err = parseAttribute(ATTRIBUTE_CHANGE_REQUEST, nil); err == nil {
		t.Error(shouldNotPass)
	}
	if _, err = parseAttribute(ATTRIBUTE_CHANGE_REQUEST, b); err == nil {
		t.Error(shouldNotPass)
	}

}

func TestMappedAddressAttribute(t *testing.T) {
	b := []byte{0x00, 0x01, 0xdd, 0xbf, 0x7f, 0x00, 0x00, 0x01}
	attr, err := parseAttribute(ATTRIBUTE_MAPPED_ADDRESS, b)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Type() != ATTRIBUTE_MAPPED_ADDRESS {
		t.Error("attr type wrong")
	}
	if attr.Length() != 8 {
		t.Error("attr length wrong")
	}
	if bytes.Compare(b, attr.Encode(nil)[4:]) != 0 {
		t.Error("attr encode wrong")
	}
	if bytes.Compare(b, attr.Value()) != 0 {
		t.Error("attr value wrong")
	}
	if attr.String() != "127.0.0.1:56767" {
		t.Error("attr string wrong")
	}
}

func TestSourceAddressAttribute(t *testing.T) {
	b := []byte{0x00, 0x01, 0x0d, 0x96, 0x7f, 0x00, 0x00, 0x01}
	attr, err := parseAttribute(ATTRIBUTE_SOURCE_ADDRESS, b)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Type() != ATTRIBUTE_SOURCE_ADDRESS {
		t.Error("attr type wrong")
	}
	if attr.Length() != 8 {
		t.Error("attr length wrong")
	}
	if bytes.Compare(b, attr.Encode(nil)[4:]) != 0 {
		t.Error("attr encode wrong")
	}
	if bytes.Compare(b, attr.Value()) != 0 {
		t.Error("attr value wrong")
	}
	if attr.String() != "127.0.0.1:3478" {
		t.Error("attr string wrong")
	}
}

func TestChangedAddressAttribute(t *testing.T) {
	b := []byte{0x00, 0x01, 0x0d, 0x97, 0x7f, 0x00, 0x00, 0x01}
	attr, err := parseAttribute(ATTRIBUTE_CHANGED_ADDRESS, b)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Type() != ATTRIBUTE_CHANGED_ADDRESS {
		t.Error("attr type wrong")
	}
	if attr.Length() != 8 {
		t.Error("attr length wrong")
	}
	if bytes.Compare(b, attr.Encode(nil)[4:]) != 0 {
		t.Error("attr encode wrong")
	}
	if bytes.Compare(b, attr.Value()) != 0 {
		t.Error("attr value wrong")
	}
	if attr.String() != "127.0.0.1:3479" {
		t.Error("attr string wrong")
	}
}

func TestXorMappedAddressAttribute(t *testing.T) {
	b := []byte{0x00, 0x01, 0xfc, 0xad, 0x5e, 0x12, 0xa4, 0x43}
	attr, err := parseAttribute(ATTRIBUTE_XOR_MAPPED_ADDRESS, b)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Type() != ATTRIBUTE_XOR_MAPPED_ADDRESS {
		t.Error("attr type wrong")
	}
	if attr.Length() != 8 {
		t.Error("attr length wrong")
	}
	if bytes.Compare(b, attr.Encode(nil)[4:]) != 0 {
		t.Error("attr encode wrong")
	}
	if bytes.Compare(b, attr.Value()) != 0 {
		t.Error("attr value wrong")
	}
	if attr.String() != "94.18.164.67:64685 => 127.0.0.1:56767" {
		t.Error("attr string wrong")
	}
}

func TestXorMappedAddressExpAttribute(t *testing.T) {
	b := []byte{0x00, 0x01, 0xfc, 0xad, 0x5e, 0x12, 0xa4, 0x43}
	attr, err := parseAttribute(ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP, b)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Type() != ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP {
		t.Error("attr type wrong")
	}
	if attr.Length() != 8 {
		t.Error("attr length wrong")
	}
	if bytes.Compare(b, attr.Encode(nil)[4:]) != 0 {
		t.Error("attr encode wrong")
	}
	if bytes.Compare(b, attr.Value()) != 0 {
		t.Error("attr value wrong")
	}
	if attr.String() != "94.18.164.67:64685 => 127.0.0.1:56767" {
		t.Error("attr string wrong")
	}
}

func TestSoftwareAttribute(t *testing.T) {
	str := "go-stun"
	b := []byte(str)
	attr, err := parseAttribute(ATTRIBUTE_SOFTWARE, b)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Type() != ATTRIBUTE_SOFTWARE {
		t.Error("attr type wrong")
	}
	b = append(b, 0x00) // include padding
	if attr.Length() != len(b) {
		t.Error("attr length wrong")
	}
	if bytes.Compare(b, attr.Value()) != 0 {
		t.Error("attr value wrong")
	}
	if attr.String() != string(b) {
		t.Error("attr string wrong")
	}
	if bytes.Compare(b, attr.Encode(nil)[4:]) != 0 {
		t.Error("attr encode wrong")
	}
}

func TestFingerprintAttribute(t *testing.T) {
	b := []byte{0x25, 0x0a, 0xbd, 0x71}
	attr, err := parseAttribute(ATTRIBUTE_FINGERPRINT, b)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Type() != ATTRIBUTE_FINGERPRINT {
		t.Error("attr type wrong")
	}
	if attr.Length() != 4 {
		t.Error("attr length wrong")
	}
	if bytes.Compare(b, attr.Encode(nil)[4:]) != 0 {
		t.Error("attr encode wrong")
	}
	if bytes.Compare(b, attr.Value()) != 0 {
		t.Error("attr value wrong")
	}
	if attr.String() != "0x250abd71" {
		t.Error("attr string wrong")
	}
}

func TestChangeRequestAttribute(t *testing.T) {
	b := []byte{0x00, 0x00, 0x00, 0x06}
	attr, err := parseAttribute(ATTRIBUTE_CHANGE_REQUEST, b)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Type() != ATTRIBUTE_CHANGE_REQUEST {
		t.Error("attr type wrong")
	}
	if attr.Length() != 4 {
		t.Error("attr length wrong")
	}
	if bytes.Compare(b, attr.Encode(nil)[4:]) != 0 {
		t.Error("attr encode wrong")
	}
	if bytes.Compare(b, attr.Value()) != 0 {
		t.Error("attr value wrong")
	}
	if attr.String() != "ip: true | port: true" {
		t.Error("attr string wrong")
	}
}
