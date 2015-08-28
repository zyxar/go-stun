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
	"net"
	"os"
	"time"
)

var (
	verbosity        bool = false
	noResponseError       = errors.New("no response received")
	partialSendError      = errors.New("partial sent")
)

const (
	/* ------------------------------------------------------------------------------------------------ */
	/* Return values for the discobery process.                                                         */
	/* ------------------------------------------------------------------------------------------------ */
	NAT_ERROR                 = iota - 1 // an error occurred.
	NAT_BLOCKED                          // UDP is blocked.
	NAT_UNKNOWN                          // the client can not determine the NAT's type.
	NAT_FULL_CONE                        // the client is behind a full cone NAT.
	NAT_SYMETRIC                         // the client is behind a symetric NAT.
	NAT_RESTRICTED                       // the client is behind a restricted NAT.
	NAT_PORT_RESTRICTED                  // the client is behind a port restricted NAT.
	NAT_NO_NAT                           // the client is not behind a NAT.
	NAT_SYMETRIC_UDP_FIREWALL            // the client is behind a symetric UDP firewall.
)

/* ------------------------------------------------------------------------------------------------ */
/* Value types for the test functions.                                                              */
/* ------------------------------------------------------------------------------------------------ */

// This type represents the specific information returned by test I.
type changedAddressInfo struct {
	family    uint16       // The "IP family" value of the attribute "CHANGED-ADDRESS".
	addr      *net.UDPAddr // The "IP:Port" of the attribute "CHANGED-ADDRESS".
	identical bool         // This flag indicates wether the local IP address id equal to the mapped one, or not.
}

// This type represents the information returned by a test.
// This is the return value for the following functions:
// - Test1
// - Test2
// - Test3
type Response struct {
	msg   *Message    // If a response has been received, then this value contains the response.
	extra interface{} // Specific information for a given test; could be: changedAddressInfo
}

/* ------------------------------------------------------------------------------------------------ */
/* API                                                                                              */
/* ------------------------------------------------------------------------------------------------ */

// This function activates the output.
//
// INPUT
// - in_verbosity: verbosity level.
// - out_verbose: pointer to a slice of strings that will be used to store the output messages.
//   If this parameter is nil, then the message will be printed in through the standard output.
func SetVerbose(verbose bool) {
	verbosity = verbose
}

type Client struct {
	addr net.UDPAddr
	conn net.Conn
}

func NewClient(addr *net.UDPAddr) (*Client, error) {
	var conn net.Conn
	var err error
	if conn, err = net.DialUDP("udp", nil, addr); err != nil {
		return nil, err
	}
	return &Client{*addr, conn}, nil
}

func (this *Client) Close() error {
	return this.conn.Close()
}

func (this *Client) send(req *Message) (resp *Message, err error) {
	resp, err = sendRequest(this.conn, req)
	return
}

func (this *Client) SendBindingRequest() (resp *Message, err error) {
	req, _ := CreateEmptyMessage(TYPE_BINDING_REQUEST, 0,
		[12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12},
	)
	if err = req.AddSoftwareAttribute("go-stun"); nil != err {
		return resp, err
	}
	if err = req.AddFingerprintAttribute(); nil != err {
		return resp, err
	}
	return this.send(req)
}

func (this *Client) SendChangeRequest(change_ip bool) (resp *Message, err error) {
	req, _ := CreateEmptyMessage(TYPE_BINDING_REQUEST, 0,
		[12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12},
	)
	if err = req.AddSoftwareAttribute("go-stun"); nil != err {
		return resp, err
	}
	if err = req.AddChangeRequestAttribute(change_ip, true); nil != err {
		return resp, err
	}
	if err = req.AddFingerprintAttribute(); nil != err {
		return resp, err
	}
	return this.send(req)
}

// This function sends a given request and returns the received msg.
//
// INPUT
// - conn: connexion to use.
// - req: the request to send.
//
// OUTPUT
// - The receive STUN msg.
// - A flag that indicates whether the client received a response or not.
//   + true: the client received a response.
//   + false: the client did not receive any response
// - The error flag.
func sendRequest(conn net.Conn, req *Message) (*Message, error) {
	var request_timeout int = 200
	var retries_count int = 0

	sent := false
	var err error
	var count int
	var b []byte = make([]byte, 1000, 1000)

	for {
		// Dump the msg.
		if verbosity && !sent {
			fmt.Fprintf(os.Stderr, "Sending REQUEST to \"%s\"\n\n%s\n", conn.RemoteAddr(), req.HexString())
			fmt.Fprintf(os.Stderr, "%s\n", req.String())
			sent = true
		}

		// Send the msg.
		p := req.Encode()
		count, err = conn.Write(p)
		if err != nil {
			return nil, err
		}
		if len(p) != count {
			return nil, partialSendError
		}

		// RFC 3489: Wait for a response.
		// Clients SHOULD retransmit the request starting with an interval of 100ms, doubling
		// every retransmit until the interval reaches 1.6s.  Retransmissions
		// continue with intervals of 1.6s until a response is received, or a
		// total of 9 requests have been sent.
		conn.SetReadDeadline(time.Now().Add(time.Duration(request_timeout) * time.Millisecond))
		if request_timeout < 1600 {
			request_timeout *= 2
		} else {
			retries_count++
		}

		// Wait for a response.
		count, err = conn.Read(b)
		if err != nil {
			if err.(net.Error).Timeout() { // See http://golang.org/src/pkg/net/timeout_test.go?h=Timeout%28%29
				if retries_count >= 9 {
					break
				}
				if verbosity {
					fmt.Fprintf(os.Stderr, "\tTimeout (%04d ms) exceeded, retry...\n", request_timeout)
				}
				continue
			}
			return nil, err
		}

		// For nice output.
		if verbosity && (retries_count > 0) {
			fmt.Fprintln(os.Stderr)
		}

		// Build the msg from the list of bytes.
		resp, err := NewMessage(b[:count])
		if nil != err {
			// The msg is not valid.
			if verbosity {
				fmt.Fprintf(os.Stderr, "\tInvalid Message: %v. Continue.", err)
			}
			continue
		}
		if verbosity {
			fmt.Fprintf(os.Stderr, "Received\n\n%s\n", resp.HexString())
			fmt.Fprintf(os.Stderr, "%s\n", resp.String())
		}

		// OK, a valid response has been received.
		return resp, nil
	}

	// No valid msg has been received.
	if verbosity {
		fmt.Fprintln(os.Stderr)
	}
	return nil, noResponseError
}

// Perform Test I.
// RFC 3489: In test I, the client sends a
//           STUN Binding Request to a server, without any flags set in the
//           CHANGE-REQUEST attribute, and without the RESPONSE-ADDRESS attribute.
//           This causes the server to send the response back to the address and
//           port that the request came from.
//
// INPUT
// - addr: this string represents the transport address of the request's destination.
//   This value should be written: "IP:Port" (IPV4) or "[IP]:Port" (IPV6).
//   If the value of this parameter is nil, then the default server's transport address will be used.
//   Note: The default server's transport address is the one defined through the call to the function "Init()".
//
// OUTPUT
// - The response.
// - The error flag.
func Test1(client *Client) (*Response, error) {
	var err error
	var mappedAddr, xoredMappedAddr *net.UDPAddr
	var response *Response = &Response{}
	var info changedAddressInfo
	var idx int

	if verbosity {
		fmt.Fprintf(os.Stderr, "\nTest I.\n\n")
	}

	response.msg, err = client.SendBindingRequest()
	if nil != err {
		return response, err
	}

	// Extracts the mapped address and the XORED mapped address.
	if idx = response.msg.MappedAddressIndex(); idx == -1 {
		return response, errors.New("mapped address not found")
	}
	_, mappedAddr = response.msg.Attribute(idx).(AddressAttribute).Decode()
	if verbosity {
		fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Mapped address", mappedAddr.String())
	}

	// Note: Some STUN servers don't set the XORED mapped address (RFC 3489 does not define XORED mapped IP address).
	if idx = response.msg.XorMappedAddressIndex(); idx != -1 {
		_, xoredMappedAddr = response.msg.Attribute(idx).(AddressAttribute).Decode()
		if verbosity {
			fmt.Fprintf(os.Stderr, "% -25s: %s\n", "XorMapped address", xoredMappedAddr.String())
		}
	} else {
		if verbosity {
			fmt.Fprintf(os.Stderr, "% -25s: %s\n", "XorMapped address", "No address given")
		}
	}

	if mappedAddr != nil && xoredMappedAddr != nil && mappedAddr.String() != xoredMappedAddr.String() {
		mappedAddr = xoredMappedAddr
	}

	// Extracts the transport address "CHANGED-ADDRESS".
	// Some servers don't set the attribute "CHANGED-ADDRESS".
	// So we consider that the lake of this attribute is not an error.
	if idx = response.msg.ChangedAddressIndex(); idx != -1 {
		info.family, info.addr = response.msg.Attribute(idx).(AddressAttribute).Decode()
	}

	// Compare local IP with mapped IP.
	if verbosity {
		fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Local address", client.conn.LocalAddr().String())
	}

	info.identical = client.conn.LocalAddr().String() == mappedAddr.String()
	response.extra = info

	return response, nil
}

// Perform Test II.
// RFC 3489: In test II, the client sends a Binding Request with both the "change IP" and "change port" flags
//           from the CHANGE-REQUEST attribute set.
//
// OUTPUT
// - A boolean that indicates wether the client received a response or not.
// - The error flag.
func Test2(client *Client) (*Response, error) {
	var err error
	var response *Response = &Response{}

	if verbosity {
		fmt.Fprintf(os.Stderr, "\nTest II.\n\n")
	}
	response.msg, err = client.SendChangeRequest(true)
	return response, err
}

// Perform Test III.
// RFC 3489: In test III, the client sends a Binding Request with only the "change port" flag set.
//
// OUTPUT
// - A boolean that indicates wether the client received a response or not.
// - The error flag.
func Test3(client *Client) (*Response, error) {
	var err error
	var response *Response = &Response{}

	if verbosity {
		fmt.Fprintf(os.Stderr, "\nTest III.\n\n")
	}
	response.msg, err = client.SendChangeRequest(false)
	return response, err
}

// Perform the discovery process.
// See RFC 3489, section "Discovery Process".
//
// OUTPUT
// - The type of NAT we are behind from.
// - The error flag.
func Discover(addr *net.UDPAddr) (int, error) {
	var err error
	var changedAddr *net.UDPAddr
	var resp *Response

	// RFC 3489: The client begins by initiating test I.  If this test yields no
	// response, the client knows right away that it is not capable of UDP
	// connectivity.  If the test produces a response, the client examines
	// the MAPPED-ADDRESS attribute.  If this address and port are the same
	// as the local IP address and port of the socket used to send the
	// request, the client knows that it is not natted.  It executes test II.

	/// ----------
	/// TEST I (a)
	/// ----------
	client, err := NewClient(addr)
	if err != nil {
		return NAT_ERROR, err
	}
	defer client.Close()
	if resp, err = Test1(client); nil != err {
		if err == noResponseError {
			fmt.Fprintf(os.Stderr, "% -25s%s\n", "Result:", "Got no response for test I.")
			fmt.Fprintf(os.Stderr, "% -25s%s\n\n", "Conclusion:", "UDP is blocked.")
			return NAT_BLOCKED, err
		}
		return NAT_ERROR, err
	}

	// Save "changed transport address" for later test.
	// Please note that some servers don't set this attribute.
	info := resp.extra.(changedAddressInfo)
	if info.addr != nil {
		if verbosity {
			fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Change IP", info.addr.IP)
			fmt.Fprintf(os.Stderr, "% -25s: %d\n", "Change port", int(info.addr.Port))
		}
		changedAddr = info.addr
	} else {
		fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "The response does not contain any \"changed\" address.")
		fmt.Fprintf(os.Stderr, "% -25s: %s\n\n", "Conclusion", "The only thing we can say is that we are behind a NAT.")
		return NAT_UNKNOWN, nil
	}

	if !info.identical { // Test I (a): The local transport address is different than the mapped transport address.
		// RFC 3489: In the event that the IP address and port of the socket did not match
		// the MAPPED-ADDRESS attribute in the response to test I, the client
		// knows that it is behind a NAT. It performs test II.

		/// -----------
		/// TEST II (a)
		/// -----------

		fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "Got a response for test I. Test I is not OK.")
		fmt.Fprintf(os.Stderr, "% -25s: %s\n\n", "Conclusion", "We are behind a NAT.")

		_, err = Test2(client)
		if nil != err && err != noResponseError {
			return NAT_ERROR, err
		} else if err == noResponseError { // Test II (a): We did not receive any valid response from the server.

			// RFC 3489:  If no response is received, it performs test I again, but this time,
			// does so to the address and port from the CHANGED-ADDRESS attribute
			// from the response to test I.

			fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "Got no response for test II. Test II is not OK.")
			fmt.Fprintf(os.Stderr, "% -25s: %s \"%s\"\n\n", "Conclusion", "Perform Test I again. This time, server's transport address is", changedAddr.String())

			/// ----------
			/// TEST I (b)
			/// ----------
			nc, err := NewClient(changedAddr)
			if err != nil {
				return NAT_ERROR, err
			}
			defer nc.Close()
			resp, err = Test1(nc)
			if nil != err {
				if err == noResponseError { // No response from the server. This should not happend.
					fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "Got no response for test I. This is unexpected!")
					fmt.Fprintf(os.Stderr, "% -25s: %s\n\n", "Conclusion", "The only thing we can say is that we are behind a NAT.")
					return NAT_UNKNOWN, nil
				}
				return NAT_ERROR, err
			}

			if !info.identical { // Test I (b)
				fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "Got a response for test I. Test I is not OK.")
				fmt.Fprintf(os.Stderr, "% -25s: %s\n\n", "Conclusion", "We are behind a symetric NAT.")
				return NAT_SYMETRIC, nil
			} else { // Test I (b)
				fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "Got a response for test I. Test I is OK.")
				fmt.Fprintf(os.Stderr, "% -25s: %s\n\n", "Conclusion", "Perform Test III.")

				/// --------
				/// TEST III
				/// --------

				_, err = Test3(client)
				if nil != err && err != noResponseError {
					return NAT_ERROR, err
				}
				if err == noResponseError {
					fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "Got no response for test III.")
					fmt.Fprintf(os.Stderr, "% -25s: %s\n\n", "Conclusion", "We are behind a \"port sestricted\" NAT.")
					return NAT_PORT_RESTRICTED, nil
				} else {
					fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "Got a response for test III.")
					fmt.Fprintf(os.Stderr, "% -25s: %s\n\n", "Conclusion", "We are behind a \"restricted\" NAT.")
					return NAT_RESTRICTED, nil
				}
			}
		} else { // TEST II (a) : We received a valid response from the server.
			// RFC 3489: If a response is received, the client knows that it is behind a \"full-cone\" NAT.
			fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "Test II is OK.")
			fmt.Fprintf(os.Stderr, "% -25s: %s\n\n", "Conclusion", "We are behind a \"full cone\" NAT.")
			return NAT_FULL_CONE, nil
		}

	} else { // Test I (a): The local transport address is identical to the mapped transport address.
		// RFC 3489: If this address and port are the same
		// as the local IP address and port of the socket used to send the
		// request, the client knows that it is not natted. It executes test II.

		fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "Got a response for test I. Test I is OK. Addresses are the same.")
		fmt.Fprintf(os.Stderr, "% -25s: %s\n\n", "Conclusion", "We are *not* behind a NAT.")

		/// -----------
		/// TEST II (b)
		/// -----------

		// If a response is received, the client knows that it has open access
		// to the Internet (or, at least, its behind a firewall that behaves
		// like a full-cone NAT, but without the translation).  If no response
		// is received, the client knows its behind a symmetric UDP firewall.

		_, err = Test2(client)
		if nil != err {
			if err == noResponseError {
				fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "Got no response for test II.")
				fmt.Fprintf(os.Stderr, "% -25s: %s\n\n", "Conclusion", "We are behind a symmetric UDP firewall.")
				return NAT_SYMETRIC_UDP_FIREWALL, nil
			}
			return NAT_ERROR, err
		}

		fmt.Fprintf(os.Stderr, "% -25s: %s\n", "Result", "Got a response for test II.")
		fmt.Fprintf(os.Stderr, "% -25s: %s\n\n", "Conclusion", "We are *not* behind a NAT.")
		return NAT_NO_NAT, nil
	}
}
