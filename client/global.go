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

package client

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/zyxar/go-stun"
)

// Verbosity level for the STUN package.
var verbosity bool = false

// This function activates the output.
//
// INPUT
// - in_verbosity: verbosity level.
// - out_verbose: pointer to a slice of strings that will be used to store the output messages.
//   If this parameter is nil, then the message will be printed in through the standard output.
func ActivateOutput(verbose bool) {
	verbosity = verbose
}

// This function sends a given request and returns the received packet.
//
// INPUT
// - in_connexion: connexion to use.
// - in_request: the request to send.
//
// OUTPUT
// - The receive STUN packet.
// - A flag that indicates whether the client received a response or not.
//   + true: the client received a response.
//   + false: the client did not receive any response
// - The error flag.
func SendRequest(in_connexion net.Conn, in_request *stun.Packet) (*stun.Packet, bool, error) {
	var rcv_packet *stun.Packet
	var request_timeout int = 100
	var retries_count int = 0

	sent := false

	for {
		var err error
		var count int
		var b []byte = make([]byte, 1000, 1000)

		// Dump the packet.
		if verbosity && !sent {
			fmt.Fprintf(os.Stderr, "Sending REQUEST to \"%s\"\n\n%s\n", in_connexion.RemoteAddr(), in_request.HexString())
			fmt.Fprintf(os.Stderr, "%s\n", in_request.String())
			sent = true
		}

		// Send the packet.
		count, err = in_connexion.Write(in_request.Bytes())
		if err != nil {
			return rcv_packet, false, errors.New(fmt.Sprintf("Can not send STUN UDP packet to server: %s", err))
		}
		if len(in_request.Bytes()) != count {
			return rcv_packet, false, errors.New(fmt.Sprintf("Can not send STUN UDP packet to server: The number of bytes sent is not valid."))
		}

		// RFC 3489: Wait for a response.
		// Clients SHOULD retransmit the request starting with an interval of 100ms, doubling
		// every retransmit until the interval reaches 1.6s.  Retransmissions
		// continue with intervals of 1.6s until a response is received, or a
		// total of 9 requests have been sent.
		in_connexion.SetReadDeadline(time.Now().Add(time.Duration(request_timeout) * time.Millisecond))
		if request_timeout < 1600 {
			request_timeout *= 2
		} else {
			retries_count++
		}

		// Wait for a response.
		count, err = in_connexion.Read(b)
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
			return rcv_packet, false, errors.New(fmt.Sprintf("Error while reading packet: %s", err))
		}

		// For nice output.
		if verbosity && (retries_count > 0) {
			fmt.Fprintln(os.Stderr, "\n")
		}

		// Build the packet from the list of bytes.
		rcv_packet, err = stun.NewPacket(b[:count])
		if nil != err {
			// The packet is not valid.
			if verbosity {
				fmt.Fprintf(os.Stderr, "\tInvalid Packet: %v. Continue.", err)
			}
			continue
		}
		if verbosity {
			fmt.Fprintf(os.Stderr, "Received\n\n%s\n", rcv_packet.HexString())
			fmt.Fprintf(os.Stderr, "%s\n", rcv_packet.String())
		}

		// OK, a valid response has been received.
		return rcv_packet, true, nil
	}

	// No valid packet has been received.
	if verbosity {
		fmt.Fprintf(os.Stderr, "")
	}
	return rcv_packet, false, nil
}
