// server.go -- create a server cert
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

	"github.com/opencoff/go-pki"
	"github.com/opencoff/go-utils"
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
	var ips IPList
	var askPw bool
	var signer string

	fs.UintVarP(&yrs, "validity", "V", yrs, "Issue server certificate with `N` years validity")
	fs.VarP(&dns, "dnsname", "d", "Add `M` to list of DNS names for this server")
	fs.VarP(&ips, "ip-address", "i", "Add `IP` to list of IP Addresses for this server")
	fs.BoolVarP(&askPw, "password", "p", false, "Ask for a password to protect the server private-key")
	fs.StringVarP(&signer, "sign-with", "s", "", "Use `S` as the signing CA [root-CA]")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	args = fs.Args()
	if len(args) < 1 {
		warn("Insufficient arguments to 'server'\n")
		fs.Usage()
	}

	ca := OpenCA(db)
	if len(signer) > 0 {
		ica, err := ca.FindCA(signer)
		if err != nil {
			die("can't find signer %s: %s", signer, err)
		}
		ca = ica
	}
	defer ca.Close()

	var pw string
	var cn string = args[0]

	if askPw {
		var err error
		prompt := fmt.Sprintf("Enter private-key password for server '%s'", cn)
		pw, err = utils.Askpass(prompt, true)
		if err != nil {
			die("Can't get password: %s", err)
		}
	}

	if strings.Index(cn, ".") > 0 {
		dns = append(dns, cn)
	}

	if len(ips) == 0 && len(dns) == 0 {
		warn("No server IP or hostnames specified; TLS Hostname verification may not be possible")
	}

	ci := &pki.CertInfo{
		Subject:  ca.Subject,
		Validity: years(yrs),

		DNSNames:    []string(dns),
		IPAddresses: []net.IP(ips),
	}
	ci.Subject.CommonName = cn

	srv, err := ca.NewServerCert(ci, pw)
	if err != nil {
		die("can't create server cert: %s", err)
	}

	Print("New server cert:\n%s\n", Cert(*srv.Certificate))
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
