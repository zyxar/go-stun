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

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/zyxar/go-stun"
	"github.com/zyxar/go-stun/client"
)

func main() {
	var (
		err        error
		serverHost *string = flag.String("host", "", "host name for the STUN server.")
		serverPort *int    = flag.Int("port", 3478, "port number for the host server.")
		verbose    *bool   = flag.Bool("verbose", false, "verbose.")
		ips        []string
		ip         string
		nat        int
	)

	// Parse the command line.
	flag.Parse()

	if "" == *serverHost {
		flag.Usage()
		fmt.Fprintln(os.Stderr, "\r\nERROR: You must specify the host name of the STUN server")
		os.Exit(1)
	}

	// Lookup the host name.
	if ips, err = net.LookupHost(*serverHost); nil != err {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
		os.Exit(1)
	} else if 0 == len(ips) {
		fmt.Fprintf(os.Stderr, "ERROR: Can not lookup host \"%s\".", *serverHost)
		os.Exit(1)
	}

	fmt.Printf("% -14s: %s\n", "Host", *serverHost)
	fmt.Printf("% -14s: %d\n", "Port", *serverPort)
	fmt.Printf("% -14s: IP%d = %s\n", "IPs", 0, ips[0])
	for i := 1; i < len(ips); i++ {
		fmt.Printf("% -14s: IP%d = %s\n", " ", i, ips[i])
	}

	if len(ips) > 1 {
		fmt.Printf("The given host name is associated to %d IP addresses.\n", len(ips))
		fmt.Printf("Which one should I use?\n")

		for {
			var response string
			var idx int

			fmt.Printf("\nPlease, enter an integer between 0 (for IP0) and %d (for IP%d).\n", len(ips)-1, len(ips))
			fmt.Scanln(&response)

			if idx, err = strconv.Atoi(response); nil != err {
				fmt.Printf("The given value (%s) is invalid.\n", response)
				continue
			} else if idx < 0 || idx >= len(ips) {
				fmt.Printf("The given value (%d) is invalid.\n", idx)
				continue
			}

			ip, err = stun.MakeTransportAddress(ips[idx], *serverPort)
			_ = err
			break
		}
	} else {
		ip, err = stun.MakeTransportAddress(ips[0], *serverPort)
		_ = err
	}
	fmt.Printf("\nUsing transport address \"%s\".\n", ip)

	// Perform discovery.
	client.Init(ip)
	client.ActivateOutput(*verbose)

	if nat, err = client.Discover(); nil != err {
		fmt.Printf("An error occured: %s\n", err)
		os.Exit(1)
	}

	// Print result.
	fmt.Println("\n\nCONCLUSION\n")

	switch nat {
	case client.NAT_ERROR:
		fmt.Println("Test failed:", err)
	case client.NAT_BLOCKED:
		fmt.Println("UDP is blocked.")
	case client.NAT_UNKNOWN:
		fmt.Println("Unexpected response from the STUN server. All we can say is that we are behind a NAT.")
	case client.NAT_FULL_CONE:
		fmt.Println("We are behind a full cone NAT.")
	case client.NAT_SYMETRIC:
		fmt.Println("We are behind a symetric NAT.")
	case client.NAT_RESTRICTED:
		fmt.Println("We are behind a restricted NAT.")
	case client.NAT_PORT_RESTRICTED:
		fmt.Println("We are behind a port restricted NAT.")
	case client.NAT_NO_NAT:
		fmt.Println("We are not behind a NAT.")
	case client.NAT_SYMETRIC_UDP_FIREWALL:
		fmt.Println("We are behind a symetric UDP firewall.")
	}
}
