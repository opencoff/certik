// export.go -- Export a certificate & key
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/opencoff/ovpn-tool/pki"
	flag "github.com/opencoff/pflag"
)

// Export a Cert & key for a given CN
func ExportCert(db string, args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	fs.Usage = func() {
		exportUsage(fs)
	}

	var outfile string
	var showCA bool

	fs.StringVarP(&outfile, "outfile", "o", "", "Write the cert to `F`.crt (and key to `F`.key)")
	fs.BoolVarP(&showCA, "ca", "", false, "Export the CA certificate")

	err := fs.Parse(args)
	if err != nil {
		die("%s", err)
	}

	ca := OpenCA(db)
	defer ca.Close()

	if showCA {
		show(ca, outfile)
		return
	}

	args = fs.Args()
	if len(args) == 0 {
		fs.Usage()
	}

	cn := args[0]

	var cout io.Writer = os.Stdout
	var kout io.Writer = os.Stdout
	if len(outfile) > 0 && outfile != "-" {
		crtfile := fmt.Sprintf("%s.crt", outfile)
		keyfile := fmt.Sprintf("%s.key", outfile)
		cfd := mustOpen(crtfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		kfd := mustOpen(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		defer cfd.Close()
		defer kfd.Close()

		cout = cfd
		kout = kfd
	}

	if c, err := ca.Find(cn); err == nil {
		c, k := c.PEM()
		cout.Write(c)
		kout.Write(k)
		return
	}

	die("Can't find server or user %s", cn)
}

// show the CA
func show(ca *pki.CA, outfile string) {
	var out io.Writer = os.Stdout

	if len(outfile) > 0 && outfile != "-" {
		if strings.LastIndex(outfile, ".crt") < 0 {
			outfile = fmt.Sprintf("%s.crt", outfile)
		}
		fd := mustOpen(outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		defer fd.Close()

		out = fd
	}

	pem := ca.PEM()
	out.Write(pem)
}

func exportUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s export: Export a server or client cert & key

Usage: %s DB export [options] name
       %s DB export --ca [options]

Where 'DB' is the CA Database file and 'NAME' is the CommonName of the
server or client credentials to be exported.

Options:
`, os.Args[0], os.Args[0], os.Args[0])

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
