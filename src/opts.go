// opts.go - multivalued command line options
//
// Implements the Value interface in github.com/opencoff/pflag
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/opencoff/pflag"
)

var (
	_ pflag.Value = &IPList{}
	_ pflag.Value = &StringList{}
)

type IPList []net.IP

func newIPList() *IPList {
	return &IPList{}
}

func (ipl *IPList) Set(s string) error {
	v := strings.Split(s, ",")
	ips := make([]net.IP, 0, 4)
	for _, x := range v {
		ip := net.ParseIP(x)
		if ip == nil {
			return fmt.Errorf("can't parse IP Address '%s'", s)
		}
		ips = append(ips, ip)
	}

	*ipl = append(*ipl, ips...)
	return nil
}

func (ipl *IPList) String() string {
	var x []string
	ips := []net.IP(*ipl)

	for i := range ips {
		x = append(x, ips[i].String())
	}
	return fmt.Sprintf("[%s]", strings.Join(x, ","))
}

type StringList []string

func newStringList() *StringList {
	return &StringList{}
}

func (i *StringList) Set(s string) error {
	v := strings.Split(s, ",")
	*i = append(*i, v...)
	return nil
}

func (i *StringList) String() string {
	return fmt.Sprintf("[%s]", strings.Join([]string(*i), ","))
}
