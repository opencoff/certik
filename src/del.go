// del.go -- Delete one or more users
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/opencoff/go-pki"
	flag "github.com/opencoff/pflag"
)

func Delete(db string, args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	fs.Usage = func() {
		delUsage(fs)
	}

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	args = fs.Args()
	if len(args) < 1 {
		warn("Insufficient arguments to 'delete'\n")
		fs.Usage()
	}

	ca := OpenCA(db)
	defer ca.Close()

	gone := 0
	for _, cn := range args {
		ck, err := ca.Find(cn)
		if err != nil {
			if !errors.Is(err, pki.ErrExpired) {
				warn("%s: %s\n", err)
				continue
			}
		}

		switch {
		case ck.IsServer:
			err = ca.RevokeServer(cn)
		case ck.IsCA:
			err = ca.RevokeCA(cn)
		default:
			err = ca.RevokeClient(cn)
		}

		if err != nil {
			warn("%s\n", err)
		} else {
			gone++
			Print("Deleted %s ..\n", cn)
		}
	}

	if gone > 0 {
		fmt.Printf("Don't forget to generate a new CRL (%s %s crl)\n", os.Args[0], db)
	}
}

func delUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s delete: Delete one or more certs ..

Usage: %s DB delete [options] CN [CN...]

Where 'DB' is the CA Database file name and 'CN' is the CommonName for the server

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}
