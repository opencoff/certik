// export.go -- Export a certificate & key
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	flag "github.com/opencoff/pflag"
)

// Export a Cert & key for a given CN
func ExportCert(db string, args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	fs.Usage = func() {
		exportUsage(fs)
	}

	var outfile string
	var chain bool
	var json, showCA bool

	fs.StringVarP(&outfile, "outfile", "o", "", "Write the cert to `F`.crt (and key to `F`.key)")
	fs.BoolVarP(&chain, "chain", "", false, "Export all the CA certs in the chain")
	fs.BoolVarP(&json, "json", "j", false, "Dump DB in JSON format")
	fs.BoolVarP(&showCA, "root-ca", "", false, "Export Root-CA in PEM format")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	ca := OpenCA(db)
	defer ca.Close()

	var cout io.Writer = os.Stdout
	if len(outfile) > 0 && outfile != "-" {
		var crtfile = outfile
		if !strings.HasSuffix(outfile, ".crt") {
			crtfile = fmt.Sprintf("%s.crt", outfile)
		}
		fd := mustOpen(crtfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		defer fd.Close()

		cout = fd
	}

	// Handle Json export first
	if json {
		err := ca.ExportJSON(cout)
		if err != nil {
			die("can't dump db: %s", err)
		}
		os.Exit(0)
	}

	if showCA {
		fmt.Fprintf(cout, "%s\n", ca.PEM())
		os.Exit(0)
	}

	args = fs.Args()
	if len(args) == 0 {
		fs.Usage()
	}

	cn := args[0]
	var kout io.Writer = os.Stdout
	if len(outfile) > 0 && outfile != "-" {
		keyfile := fmt.Sprintf("%s.key", outfile)
		kfd := mustOpen(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		defer kfd.Close()
		kout = kfd
	}

	c, err := ca.Find(cn)
	if err != nil {
		die("Can't find server or user %s", cn)
	}

	var pem []byte
	var key []byte
	if c.IsCA && chain {
		cas, err := ca.ChainFor(c)
		if err != nil {
			die("can't find cert chain: %s", err)
		}

		var cw bytes.Buffer
		for i := range cas {
			ck := cas[i]
			cw.Write(ck.PEM())
		}

		pem = cw.Bytes()
		_, key = c.PEM()
	} else {
		pem, key = c.PEM()
	}

	cout.Write(pem)
	kout.Write(key)
}

func exportUsage(fs *flag.FlagSet) {
	prog := os.Args[0]
	fmt.Printf(`%s export: Export a server or client cert & key

Usage: %s DB export [options] name
       %s DB export --root-ca [options]
       %s DB export --json [options]

Where 'DB' is the CA Database file and 'NAME' is the CommonName of the
server or client credentials to be exported.

Options:
`, prog, prog, prog, prog)

	fs.PrintDefaults()
	os.Exit(0)
}

func mustOpen(fn string, flag int) *os.File {
	fdk, err := os.OpenFile(fn, flag, 0600)
	if err != nil {
		die("can't open file %s: %s", fn, err)
	}
	return fdk
}

// EOF
