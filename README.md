## TL;DR
This is an opinionated single-file TLS certificate manager.
It has _no_ dependencies on any other external tool
such as openssl. It is a simpler replacement for openssl(1).

## Features
* Uses a single [boltdb](https://github.com/etcd/bbolt) instance to store the
  certificates and keys.
* All data strored in the database is encrypted with keys derived from a user
  supplied CA passphrase.
* The certificates and keys are opinionated:
   * Secp256k1 EC certificate private keys
   * "SSL-Server" attribute set on server certificates (nsCertType)
   * "SSL-Client" attribute set on client certificates (nsCertType)
   * ECDSA with SHA512 is used as the signature algorithm

## Building certiki
You will need a fairly recent golang toolchain (>1.10):

    $ git clone https://github.com/opencoff/certiki
    $ cd certiki
    $ ./build -s

The build script puts the binary in a platform specific directory:

* macOS: `bin/darwin-amd64`
* Linux: `bin/linux-amd64`
* OpenBSD: `bin/openbsd-amd64`

And so on. The build script can generate a fully standalone
statically-linked binary on platforms that support it. To build
statically linked binaries, use `build -s`.

You can also do cross-platform builds for any supported OS, Arch
combination supported by the golang toolchain. e.g., on macOS,
to build a statically linked binary for linux-amd64 architecture:

    $ ./build -s --arch linux-amd64

## Invoking certiki
The common pattern for invoking certiki is:

    certiki DB CMD [options] [arguments]

Where:
* *DB* is the name of the certificate store (database). This is a
  [boltdb](https://github.com/etcd/bbolt) instance.

* *CMD* is a command - one of `init`, `server`, `client`, `export`,
  `list`, `delete`, `crl`.

The tool writes the certificates, keys into an encrypted boltdb instance.

The tool comes with builtin help:

    $ ./bin/openbsd-amd64/certiki --help

Every subcommand comes with its own help; but, requires you to at least
supply a database name as the first argument. e.g.,

    $ ./bin/openbsd-amd64/certiki foo.db server --help

## Common Workflows
In what follows, we will assume that you have built certiki and
installed somewhere in your `$PATH`.

### Initialize a new CA
Before any certificates are generated, one must first create a CA and
initialize the certificate DB:

    $ certiki -v foo.db init my-CA

You can see the generated CA certificate via two ways:

1. Using `-v` for the certiki's global options
2. Using the `list` command with the `--ca` option.

In general, using the `-v` global option when generating the CA, server
or client certificates will print the certificate to stdout at the end.

The CA can be initialized with additional data such as Organization Name,
Organization Unit Name etc. See `init --help` for additional details.

The default lifetime of the CA is 5 years; you can change this via
the `-V` (`--validity`) option to "init".

### Create a TLS server certificate & key pair
An TLS server needs a few things:
* A server common name - so client can either address it by DNS Name.
* Optionally, an IP Address

Creating a new server certificate/key pair:

    $ certiki -v foo.db server -i IP.ADDR.ES server.domain.name

Of course, you should use the appropriate values for `IP.ADDR.ES`
and `server.domain.name` for your setup.

The IP Address and Server FQDN show up in the certificate as
Certificate.IPAddress and Certificate.Sibject.CommonName.
Additionally, the server FQDN also shows up in Certificate.DNSNames.

You can request the server certificate to have a different
validity via the `V` (`--validity`) option; this option takes the
value in units of years.

You can of course create as many server certificates as needed.

### Create a TLS client (user) certificate & key pair
An TLS client certificate is quite simple - it just needs a
common name. For convenience, you may use the email address as the 
common Name.

    $ certiki -v foo.db client user@domain.name

You can ask the client private key to be encrypted with a user
supplied passphrase by using the `-p` or `--password` option to the
`client` command.  You can request the client certificate to have
a different validity via the `V` (`--validity`) option; this option
takes the value in units of years.

### Delete a certificate & key from the Cert Database
Once in a while you will want to delete users and prevent them from
connecting to the TLS server. E.g.,

    $ certiki -v foo.db delete user@domain.name user2@domain

This only deletes the users from the certificate DB. You still need
to generate a new CRL (Certificate Revocation List) and push it to
your server. See the next workflow.

### Generate a CRL from Revoked Certificates
Once a user is deleted from the system, you will need to generate a
new CRL and push it to the server. The command to generate a new
CRL:

    $ certiki -v foo.db crl -o crl.pem

This write the PEM encoded CRL to `crl.pem`. You must copy this file
to the OpenVPN server and reload (or restart) it.

You can also just view a full list of revoked users:

    $ certiki foo.db crl --list

### See list of certificates managed by this CA
To see a list of certificates in the database:

    $ certiki foo.db list

### Exporting a Certificate & Key
While the tool manages certificates, for use in a TLS client or server,
we need to export the CA certificate, server certificate and key.
To export a certificate & key configuration:

    $ certiki foo.db export server.domain.name
    $ certiki foo.db export user@domain.name

This prints the PEM encoded cert & key to stdout. To write each to a
separate file:

    $ certiki foo.db export server.domain.name -o server

This will write the certificate into `server.crt` and key to
`server.key`.

### Exporting the CA Certificate
The CA certificate anchors the root of trust; so, the TLS Server and
Client both need the CA Certificate. One exports it like so:

    $ certiki foo.db export --ca -o ca.crt


## TODO

* Tests

# Development Notes
If you wish to hack on this, notes here might be useful.

The code is organized as a library & command line frontend for that library.

* We use go module support; you will need go 1.10+ or later

* The build script `build` is a shell script to build the program.
  It does two very important things:
    * Puts the binary in an OS+Arch specific directory
    * Injects a git version-tag into the final binary ("linker resolved symbol")

* Database encryption:
    * User passphrase is first expanded to 64 bytes by hashing it via SHA-512.
    * Every encryption uses a different key generated via Argon2i KDF. The
      KDF uses the expanded passphrase with a random 32 byte salt.
    * The KDF parameters are hardcoded in `db.go:kdf()` function;
      it is currently `Time = 1`, `Mem = 1048576`, and `Threads = 8`.
    * Database keys are entangled with the expanded passphrase via HMAC-SHA256.
    * Database entries are individually encrypted in AEAD (AES-256-GCM) mode.
      The AEAD nonce size is 32 bytes (instead of the golang default
      of 12 bytes).
    * Each encrypt operation uses a different key derived as above.
    * The KDF salt is used as additional data in the AEAD construction.
    * The AEAD nonce is a SHA-256 hash of the KDF salt; this saves
      us from having to generate & save another random quantity.

## Guide to Source Code
* `internal/ovpn/`: Core library that does certificate management and
  storage.

    - `cert.go`:   Certificate issuance & query routines
    - `db.go`:     Cert storage in a boltdb instance
    - `cipher.go`: DB encryption/decryption routines
    - `str.go`:    Utility function to print a certificate in string format

* `internal/utils`: Misc utilities for asking interactive password

* `src/`: Command line interface to the library capabilities. Each
  command is in its own file.

