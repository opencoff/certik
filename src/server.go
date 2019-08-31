// server.go -- server cert creation
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
	"os"
	"strings"

	"github.com/opencoff/ovpn-tool/pki"
	flag "github.com/opencoff/pflag"
)

// Implement the 'server' command
func ServerCert(db string, args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	fs.Usage = func() {
		serverUsage(fs)
	}

	var yrs uint = 2
	var dns StringList
	var ip net.IP
	var port uint16 = 1194

	fs.UintVarP(&yrs, "validity", "V", yrs, "Issue server certificate with `N` years validity")
	fs.VarP(&dns, "dnsname", "d", "Add `M` to list of DNS names for this server")
	fs.IPVarP(&ip, "ip-address", "i", ip, "Use `S` as the server listening IP address")
	fs.Uint16VarP(&port, "port", "p", port, "Use `P` as the server listening port number")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	args = fs.Args()
	if len(args) < 1 {
		warn("Insufficient arguments to 'init'\n")
		fs.Usage()
	}

	cn := args[0]
	if strings.Index(cn, ".") > 0 {
		dns.V = append(dns.V, cn)
	}

	if len(ip) == 0 && len(dns.V) == 0 {
		warn("No server IP or hostnames specified; generated configs may be incomplete..")
	}

	ca := OpenCA(db)
	defer ca.Close()

	ci := &pki.CertInfo{
		Subject:  ca.Crt.Subject,
		Validity: years(yrs),

		DNSNames:  dns.V,
		IPAddress: ip,
	}

	ci.Subject.CommonName = cn

	srv, err := ca.NewServerCert(ci, "")
	if err != nil {
		die("can't create server cert: %s", err)
	}

	Print("New server cert:\n%s\n", Cert(*srv.Crt))
}

func serverUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s server: Issue a new server certificate

Usage: %s DB server [options] CN

Where 'DB' is the CA Database file name and 'CN' is the CommonName for the server

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}
