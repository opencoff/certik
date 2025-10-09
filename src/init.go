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
	"io/ioutil"
	"os"
	"time"

	"github.com/opencoff/go-pki"
	"github.com/opencoff/go-utils"
	flag "github.com/opencoff/pflag"
)

// Get a password if needed
func getPass(dbname string, envpw string, nopw, confirm bool) string {
	if nopw {
		return ""
	}

	var pws string
	var err error
	if len(envpw) > 0 {
		pws = os.Getenv(envpw)
	} else {
		pws, err = utils.Askpass("Enter password for DB", confirm)
		if err != nil {
			die("%s", err)
		}
	}
	return pws
}

// Open an existing CA or fail
func OpenCA(db string, envpw string, nopw bool) *pki.CA {
	pw := getPass(db, envpw, nopw, false)
	p := pki.Config{
		Passwd: pw,
	}
	ca, err := pki.New(&p, db, false)
	if err != nil {
		die("%s", err)
	}
	return ca
}

// initialize a CA in 'dbfile' or import from json
func InitCmd(dbfile string, args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fs.Usage = func() {
		initUsage(fs)
	}

	var country, org, ou string
	var yrs uint
	var envpw, from string
	var nopw bool

	fs.StringVarP(&country, "country", "c", "US", "Use `C` as the country name")
	fs.StringVarP(&org, "organization", "O", "", "Use `O` as the organization name")
	fs.StringVarP(&ou, "organization-unit", "u", "", "Use `U` as the organization unit name")
	fs.UintVarP(&yrs, "validity", "V", 5, "Issue CA root cert with `N` years validity")
	fs.StringVarP(&from, "from-json", "j", "", "Initialize from an exported JSON dump")
	fs.StringVarP(&envpw, "env-password", "E", "", "Use passphrase from environment variable `E`")
	fs.BoolVarP(&nopw, "no-password", "", false, "Don't ask for a password for the private key")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	var cn string

	args = fs.Args()
	if len(args) <= 0 && len(from) == 0 {
		fs.Usage()
		os.Exit(1)
	}

	pw := getPass(dbfile, envpw, nopw, true)

	var ca *pki.CA
	if len(from) > 0 {
		js, err := ioutil.ReadFile(from)
		if err != nil {
			die("can't read json: %s", err)
		}

		cfg := &pki.Config{
			Passwd: pw,
		}
		ca, err = pki.NewFromJSON(cfg, dbfile, string(js))
		if err != nil {
			die("%s", err)
		}
	} else if len(args) > 0 {
		var err error

		cn = args[0]
		p := pki.Config{
			Passwd:   pw,
			Validity: years(yrs),

			Subject: pkix.Name{
				Country:            []string{country},
				Organization:       []string{org},
				OrganizationalUnit: []string{ou},
				CommonName:         cn,
			},
		}
		ca, err = pki.New(&p, dbfile, true)
		if err != nil {
			die("%s", err)
		}
	} else {
		fs.Usage()
		os.Exit(1)
	}

	Print("New CA cert:\n%s\n", Cert(*ca.Certificate))
}

// initialize a CA in 'dbfile' or read an already initialized CA

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
