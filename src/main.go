// main.go - simple cert manager
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/opencoff/go-pki"
	"github.com/opencoff/go-utils"
	flag "github.com/opencoff/pflag"
)

var Verbose bool

func main() {
	flag.SetInterspersed(false)

	verFlag := flag.BoolP("version", "", false, "Show version info and quit")
	flag.BoolVarP(&Verbose, "verbose", "v", false, "Show verbose output")

	flag.Usage = func() {
		fmt.Printf(
			`%s - Opinionated PKI Tool

Usage: %s [options] DB CMD [args..]

Where 'DB' points to the certificate database, and 'CMD' is one of:

    init              Initialize a new CA and cert store
    intermediate      Generate an intermediate CA
    server            Create a new server certificate
    list, show        List one or all certificates in the DB
    export            Export a client or server certificate & key
    delete	      Delete a user, server or intermediate CA
    user, client      Create a new user/client certificate
    crl		      List revoked certificates or generate CRL
    passwd            Change the DB encryption password
    help	      Show this help message

Options:
`, path.Base(os.Args[0]), os.Args[0])
		flag.PrintDefaults()
		os.Stdout.Sync()
		os.Exit(0)
	}

	flag.Parse()

	if *verFlag {
		fmt.Printf("%s - %s [%s; %s]\n", path.Base(os.Args[0]), ProductVersion, RepoVersion, Buildtime)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) < 1 {
		die("Insufficient arguments!\nTry '%s -h'\n", os.Args[0])
	}

	db := args[0]
	// handle the common case of people forgetting the DB
	switch strings.ToLower(db) {
	case "help", "hel", "he":
		flag.Usage()
		os.Exit(1)
	default:
	}

	args = args[1:]
	if len(args) < 1 {
		die("Insufficient arguments; missing command!\nTry '%s -h'\n", os.Args[0])
	}

	var cmds = map[string]func(string, []string){
		"init":         InitCmd,
		"server":       ServerCert,
		"user":         UserCert,
		"delete":       Delete,
		"client":       UserCert,
		"export":       ExportCert,
		"show":         ListCert,
		"list":         ListCert,
		"crl":          ListCRL,
		"intermediate": IntermediateCA,
		"passwd":       ChangePasswd,
	}
	words := make([]string, len(cmds))
	for k := range cmds {
		words = append(words, k)
	}
	ab := utils.Abbrev(words)
	// handle the common case of people forgetting the DB
	cmd := strings.ToLower(args[0])
	canon, ok := ab[cmd]
	if !ok {
		die("unknown command '%s'; Try '%s --help'", cmd, os.Args[0])
	}

	fp, ok := cmds[canon]
	if !ok {
		die("can't find command '%s'", canon)
	}

	fp(db, args[1:])
}

type Cert x509.Certificate

func (z Cert) String() string {
	c := x509.Certificate(z)
	s, err := pki.CertificateText(&c)
	if err != nil {
		s = fmt.Sprintf("can't stringify %x (%s)", c.SerialNumber, err)
	}
	return s
}

// Only show output if needed
func Print(format string, v ...interface{}) {
	if Verbose {
		s := fmt.Sprintf(format, v...)
		if n := len(s); s[n-1] != '\n' {
			s += "\n"
		}
		os.Stdout.WriteString(s)
		os.Stdout.Sync()
	}
}

// This will be filled in by "build"
var RepoVersion string = "UNDEFINED"
var Buildtime string = "UNDEFINED"
var ProductVersion string = "UNDEFINED"
