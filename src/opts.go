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

type IPList struct {
	V []net.IP
}

func newIPList() *IPList {
	v := &IPList{
		V: make([]net.IP, 0, 4),
	}
	return v
}

func (i *IPList) Set(s string) error {
	v := strings.Split(s, ",")
	for _, x := range v {
		ip := net.ParseIP(x)
		if ip == nil {
			return fmt.Errorf("can't parse IP Address '%s'", s)
		}
		i.V = append(i.V, ip)
	}

	return nil
}

func (i *IPList) String() string {
	var x []string

	for _, i := range i.V {
		x = append(x, i.String())
	}
	z := strings.Join(x, ",")
	return fmt.Sprintf("[%s]", z)
}

type StringList struct {
	V []string
}

func newStringList() *StringList {
	v := &StringList{
		V: make([]string, 0, 4),
	}
	return v
}

func (i *StringList) Set(s string) error {
	v := strings.Split(s, ",")
	i.V = append(i.V, v...)
	return nil
}

func (i *StringList) String() string {
	z := strings.Join(i.V, ",")
	return fmt.Sprintf("[%s]", z)
}
