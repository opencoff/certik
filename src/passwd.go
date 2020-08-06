// passwd.go - change DB password
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
	"github.com/opencoff/go-utils"
	flag "github.com/opencoff/pflag"
)

// change DB encryption password
func ChangePasswd(dbfile string, args []string) {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	fs.Usage = func() {
		passwdUsage(fs)
	}

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	var oldpw string
	var newpw string

	oldpw, err = utils.Askpass("Enter old password for DB", false)
	if err != nil {
		die("%s", err)
	}

	p := pki.Config{
		Passwd: oldpw,
	}

	ca, err := pki.New(&p, oldpw, false)
	if err != nil {
		die("can't open CA: %s", err)
	}

	defer ca.Close()

	newpw, err = utils.Askpass("Enter new password for DB", true)
	if err != nil {
		die("%s", err)
	}

	err = ca.Rekey(newpw)
	if err != nil {
		die("%s", err)
	}
}

func passwdUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s passwd: Change the DB encryption password

This command changes the DB encryption password with a new user supplied
passphrase.

Usage: %s DB passwd

Where 'DB' is the CA Database file name.

Options:
`, os.Args[0], os.Args[0])

	fs.PrintDefaults()
	os.Exit(0)
}
