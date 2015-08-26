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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type attribute []byte

func (attr attribute) decode() (uint16, *net.UDPAddr) {
	return binary.BigEndian.Uint16(attr[0:2]),
		&net.UDPAddr{
			IP:   parseIP(attr[4:]),
			Port: int(binary.BigEndian.Uint16(attr[2:4])),
		}
}

type Attribute interface {
	String() string
	Encode([]byte) []byte
	Value() []byte
	Len() int
	Cap() int
	Type() uint16
}

type AddressAttribute interface {
	Attribute
	Decode() (uint16, *net.UDPAddr)
}

type mappedAddressAttribute attribute
type sourceAddressAttribute attribute
type changedAddressAttribute attribute
type xorMappedAddressAttribute attribute
type xorMappedAddressExpAttribute attribute
type softwareAttribute attribute
type fingerprintAttribute attribute
type changeRequestAttribute attribute

func (mappedAddressAttribute) Type() uint16       { return ATTRIBUTE_MAPPED_ADDRESS }
func (sourceAddressAttribute) Type() uint16       { return ATTRIBUTE_SOURCE_ADDRESS }
func (changedAddressAttribute) Type() uint16      { return ATTRIBUTE_CHANGED_ADDRESS }
func (xorMappedAddressAttribute) Type() uint16    { return ATTRIBUTE_XOR_MAPPED_ADDRESS }
func (xorMappedAddressExpAttribute) Type() uint16 { return ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP }
func (softwareAttribute) Type() uint16            { return ATTRIBUTE_SOFTWARE }
func (fingerprintAttribute) Type() uint16         { return ATTRIBUTE_FINGERPRINT }
func (changeRequestAttribute) Type() uint16       { return ATTRIBUTE_CHANGE_REQUEST }

func (this mappedAddressAttribute) Len() int       { return len(this) }
func (this sourceAddressAttribute) Len() int       { return len(this) }
func (this changedAddressAttribute) Len() int      { return len(this) }
func (this xorMappedAddressAttribute) Len() int    { return len(this) }
func (this xorMappedAddressExpAttribute) Len() int { return len(this) }
func (this softwareAttribute) Len() int            { return len(this) }
func (this fingerprintAttribute) Len() int         { return len(this) }
func (this changeRequestAttribute) Len() int       { return len(this) }

func (this mappedAddressAttribute) Cap() int       { return cap(this) }
func (this sourceAddressAttribute) Cap() int       { return cap(this) }
func (this changedAddressAttribute) Cap() int      { return cap(this) }
func (this xorMappedAddressAttribute) Cap() int    { return cap(this) }
func (this xorMappedAddressExpAttribute) Cap() int { return cap(this) }
func (this softwareAttribute) Cap() int            { return cap(this) }
func (this fingerprintAttribute) Cap() int         { return cap(this) }
func (this changeRequestAttribute) Cap() int       { return cap(this) }

func (this mappedAddressAttribute) Value() []byte       { return this }
func (this sourceAddressAttribute) Value() []byte       { return this }
func (this changedAddressAttribute) Value() []byte      { return this }
func (this xorMappedAddressAttribute) Value() []byte    { return this }
func (this xorMappedAddressExpAttribute) Value() []byte { return this }
func (this softwareAttribute) Value() []byte            { return this }
func (this fingerprintAttribute) Value() []byte         { return this }
func (this changeRequestAttribute) Value() []byte       { return this }

func (this mappedAddressAttribute) Encode(p []byte) []byte {
	if p == nil || cap(p) < 4+this.Cap() {
		p = make([]byte, 4+this.Cap())
	}
	binary.BigEndian.PutUint16(p[:2], this.Type())
	binary.BigEndian.PutUint16(p[2:4], uint16(this.Len()))
	copy(p[4:], this)
	return p
}
func (this sourceAddressAttribute) Encode(p []byte) []byte {
	if p == nil || cap(p) < 4+this.Cap() {
		p = make([]byte, 4+this.Cap())
	}
	binary.BigEndian.PutUint16(p[:2], this.Type())
	binary.BigEndian.PutUint16(p[2:4], uint16(this.Len()))
	copy(p[4:], this)
	return p
}
func (this changedAddressAttribute) Encode(p []byte) []byte {
	if p == nil || cap(p) < 4+this.Cap() {
		p = make([]byte, 4+this.Cap())
	}
	binary.BigEndian.PutUint16(p[:2], this.Type())
	binary.BigEndian.PutUint16(p[2:4], uint16(this.Len()))
	copy(p[4:], this)
	return p
}
func (this xorMappedAddressAttribute) Encode(p []byte) []byte {
	if p == nil || cap(p) < 4+this.Cap() {
		p = make([]byte, 4+this.Cap())
	}
	binary.BigEndian.PutUint16(p[:2], this.Type())
	binary.BigEndian.PutUint16(p[2:4], uint16(this.Len()))
	copy(p[4:], this)
	return p
}
func (this xorMappedAddressExpAttribute) Encode(p []byte) []byte {
	if p == nil || cap(p) < 4+this.Cap() {
		p = make([]byte, 4+this.Cap())
	}
	binary.BigEndian.PutUint16(p[:2], this.Type())
	binary.BigEndian.PutUint16(p[2:4], uint16(this.Len()))
	copy(p[4:], this)
	return p
}
func (this softwareAttribute) Encode(p []byte) []byte {
	if p == nil || cap(p) < 4+this.Cap() {
		p = make([]byte, 4+this.Cap())
	}
	binary.BigEndian.PutUint16(p[:2], this.Type())
	binary.BigEndian.PutUint16(p[2:4], uint16(this.Len()))
	copy(p[4:], this)
	return p
}
func (this fingerprintAttribute) Encode(p []byte) []byte {
	if p == nil || cap(p) < 4+this.Cap() {
		p = make([]byte, 4+this.Cap())
	}
	binary.BigEndian.PutUint16(p[:2], this.Type())
	binary.BigEndian.PutUint16(p[2:4], uint16(this.Len()))
	copy(p[4:], this)
	return p
}
func (this changeRequestAttribute) Encode(p []byte) []byte {
	if p == nil || cap(p) < 4+this.Cap() {
		p = make([]byte, 4+this.Cap())
	}
	binary.BigEndian.PutUint16(p[:2], this.Type())
	binary.BigEndian.PutUint16(p[2:4], uint16(this.Len()))
	copy(p[4:], this)
	return p
}

func (this mappedAddressAttribute) String() string {
	_, addr := attribute(this).decode()
	return addr.String()
}

func (this sourceAddressAttribute) String() string {
	_, addr := attribute(this).decode()
	return addr.String()
}

func (this changedAddressAttribute) String() string {
	_, addr := attribute(this).decode()
	return addr.String()
}

func (this xorMappedAddressAttribute) String() string {
	_, addr := attribute(this).decode()
	_, addrXor := this.Decode()
	return fmt.Sprintf("%s => %s", addr.String(), addrXor.String())
}

func (this xorMappedAddressExpAttribute) String() string {
	return xorMappedAddressAttribute(this).String()
}

func (this softwareAttribute) String() string { return string(this) }

func (this fingerprintAttribute) String() string {
	return fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(this))
}

func (this changeRequestAttribute) String() string {
	return fmt.Sprintf("ip: %v | port: %v", (0x04|this[3]) != 0, (0x02|this[3]) != 0)
}

func (this mappedAddressAttribute) Decode() (uint16, *net.UDPAddr) {
	return attribute(this).decode()
}

func (this sourceAddressAttribute) Decode() (uint16, *net.UDPAddr) {
	return attribute(this).decode()
}

func (this changedAddressAttribute) Decode() (uint16, *net.UDPAddr) {
	return attribute(this).decode()
}

func (this xorMappedAddressAttribute) Decode() (uint16, *net.UDPAddr) {
	cookie := []byte{0x21, 0x12, 0xA4, 0x42} // 0x2112A442
	b := make([]byte, len(this))
	copy(b, this)
	for i := 0; i < len(b)-4; i++ {
		b[i+4] ^= cookie[i%4]
	}
	b[2] ^= 0x21
	b[3] ^= 0x12
	return attribute(b).decode()
}

func (this xorMappedAddressExpAttribute) Decode() (uint16, *net.UDPAddr) {
	return xorMappedAddressAttribute(this).Decode()
}

func ParseAttribute(b []byte) (Attribute, error) {
	vtype := binary.BigEndian.Uint16(b[:2])   // Type of the attribute.
	length := binary.BigEndian.Uint16(b[2:4]) // Length of the attribute, without the padding
	value := b[4 : 4+length]                  // The value.
	return parseAttribute(vtype, value)
}

func parseAttribute(_type uint16, b []byte) (Attribute, error) {
	var err = errors.New("invalid bytes")
	length := len(b)
	if 0 != length%4 && rfc == RFC3489 && _type != ATTRIBUTE_SOFTWARE {
		return nil, err
	} else if len(b) > 65535 {
		return nil, err
	}
	b = padding(b)[:length]
	switch _type {
	case ATTRIBUTE_MAPPED_ADDRESS:
		if len(b) != 8 && len(b) != 20 {
			return nil, err
		}
		return mappedAddressAttribute(b), nil
	case ATTRIBUTE_SOURCE_ADDRESS:
		if len(b) != 8 && len(b) != 20 {
			return nil, err
		}
		return sourceAddressAttribute(b), nil
	case ATTRIBUTE_CHANGED_ADDRESS:
		if len(b) != 8 && len(b) != 20 {
			return nil, err
		}
		return changedAddressAttribute(b), nil
	case ATTRIBUTE_XOR_MAPPED_ADDRESS:
		if len(b) != 8 && len(b) != 20 {
			return nil, err
		}
		return xorMappedAddressAttribute(b), nil
	case ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP:
		if len(b) != 8 && len(b) != 20 {
			return nil, err
		}
		return xorMappedAddressExpAttribute(b), nil
	case ATTRIBUTE_SOFTWARE:
		return softwareAttribute(b), nil
	case ATTRIBUTE_FINGERPRINT:
		if len(b) != 4 {
			return nil, err
		}
		return fingerprintAttribute(b), nil
	case ATTRIBUTE_CHANGE_REQUEST:
		if len(b) != 4 {
			return nil, err
		}
		return changeRequestAttribute(b), nil
	default:
		if _, ok := attribute_names[_type]; ok {
			return nil, errors.New("unsupported type")
		}
	}
	return nil, errors.New("invalid type")
}
