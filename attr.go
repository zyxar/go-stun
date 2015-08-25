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

type attribute []byte

func ParseAttribute(b []byte) Attribute {
	return nil
}

type Attribute interface {
	String() string
	Encode() []byte
	Length() int
	Type() uint16
}

type MappedAddressAttribute attribute
type SourceAddressAttribute attribute
type ChangedAddressAttribute attribute
type XorMappedAddressAttribute attribute
type XorMappedAddressExpAttribute attribute
type SoftwareAttribute attribute
type FingerprintAttribute attribute
type ChangeRequestAttribute attribute

func (MappedAddressAttribute) Type() uint16       { return ATTRIBUTE_MAPPED_ADDRESS }
func (SourceAddressAttribute) Type() uint16       { return ATTRIBUTE_SOURCE_ADDRESS }
func (ChangedAddressAttribute) Type() uint16      { return ATTRIBUTE_CHANGED_ADDRESS }
func (XorMappedAddressAttribute) Type() uint16    { return ATTRIBUTE_XOR_MAPPED_ADDRESS }
func (XorMappedAddressExpAttribute) Type() uint16 { return ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP }
func (SoftwareAttribute) Type() uint16            { return ATTRIBUTE_SOFTWARE }
func (FingerprintAttribute) Type() uint16         { return ATTRIBUTE_FINGERPRINT }
func (ChangeRequestAttribute) Type() uint16       { return ATTRIBUTE_CHANGE_REQUEST }
