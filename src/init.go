// init.go - init command implementation
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"crypto/x509/pkix"
	"fmt"
	"os"
	"time"

	"github.com/opencoff/ovpn-tool/pki"
	"github.com/opencoff/go-utils"
	flag "github.com/opencoff/pflag"
)

// Initialize a new CA or an existing CA
func InitCmd(db string, args []string) {
	ca := initCA(db, args, true)
	ca.Close()
}

// Open an existing CA or fail
func OpenCA(db string) *pki.CA {
	return initCA(db, []string{}, false)
}

// initialize a CA in 'dbfile' or read an already initialized CA
func initCA(dbfile string, args []string, init bool) *pki.CA {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fs.Usage = func() {
		initUsage(fs)
	}

	var country, org, ou string
	var yrs uint

	fs.StringVarP(&country, "country", "c", "US", "Use `C` as the country name")
	fs.StringVarP(&org, "organization", "O", "", "Use `O` as the organization name")
	fs.StringVarP(&ou, "organization-unit", "u", "", "Use `U` as the organization unit name")
	fs.UintVarP(&yrs, "validity", "V", 5, "Issue CA root cert with `N` years validity")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	var cn string
	var creat bool
	var pw string

	args = fs.Args()
	if len(args) > 0 {
		cn = args[0]
		creat = true

		pw, err = utils.Askpass("Enter password for CA private key", true)
		if err != nil {
			die("%s", err)
		}
	} else {
		if init {
			fs.Usage()
			os.Exit(1)
		}

		// we only ask _once_
		pw, err = utils.Askpass("Enter password for CA private key", false)
		if err != nil {
			die("%s", err)
		}
	}

	p := pki.CAparams{
		Subject: pkix.Name{
			Country:            []string{country},
			Organization:       []string{org},
			OrganizationalUnit: []string{ou},
			CommonName:         cn,
		},

		Passwd:          pw,
		CreateIfMissing: creat,
		Validity:        years(yrs),
		DBfile:          dbfile,
	}

	ca, err := pki.NewCA(&p)
	if err != nil {
		die("%s", err)
	}

	Print("New CA cert:\n%s\n", Cert(*ca.Crt))

	return ca
}

func initUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s init: Initialize a new CA and cert store

This command initializes the given CA database and creates
a new root CA if needed.

Usage: %s DB init [options] CN

Where 'DB' is the CA Database file name and 'CN' is the CommonName for the CA.

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}

// convert duration in years to time.Duration
// 365.25 days/year * 24 hours/day
// .25 days/year = 24 hours / 4 = 6 hrs
func years(n uint) time.Duration {
	day := 24 * time.Hour
	return (6 * time.Hour) + (time.Duration(n*365) * day)
}
