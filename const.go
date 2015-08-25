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

const (
	RFC3489 = iota
	RFC5389
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
