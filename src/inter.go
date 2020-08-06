// inter.go - intermediate CA command implementation
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	"os"

	"github.com/opencoff/go-pki"
	flag "github.com/opencoff/pflag"
)

// Initialize a new CA or an existing CA
func IntermediateCA(db string, args []string) {

	fs := flag.NewFlagSet("intermediate-ca", flag.ExitOnError)
	fs.Usage = func() {
		intermediateCAUsage(fs)
	}

	var yrs uint = 2
	var signer string

	fs.UintVarP(&yrs, "validity", "V", 5, "Issue CA root cert with `N` years validity")
	fs.StringVarP(&signer, "sign-with", "s", "", "Use `S` as the signing CA [root-CA]")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}
	args = fs.Args()
	if len(args) < 1 {
		warn("Insufficient arguments to 'intermediate-ca'\n")
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

	cn := args[0]

	ci := &pki.CertInfo{
		Subject:  ca.Subject,
		Validity: years(yrs),
	}

	ci.Subject.CommonName = cn
	ica, err := ca.NewIntermediateCA(ci)
	if err != nil {
		die("%s", err)
	}
	Print("New intermediate CA:\n%s\n", Cert(*ica.Certificate))
}

func intermediateCAUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s intermediate-ca: Create an intermediate CA.

This command creates an intermediate CA chained to the root CA.

Usage: %s DB intermediate-ca [options] CN

Where 'DB' is the CA Database file name and 'CN' is the CommonName for the intermediate CA.

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}
