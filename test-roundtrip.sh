#! /usr/bin/env bash

set -e
eval $(go env)

bindir=./bin/${GOOS}-${GOARCH}
bin=$bindir/certik

db=test.db
Nopass="--no-password"

set -x
test -f $db && rm -f $db
$bin $db init   $Nopass my-ca
$bin $db inter  $Nopass server-ca
$bin $db inter  $Nopass client-ca
$bin $db server $Nopass -s server-ca a.b.com
$bin $db user   $Nopass -s client-ca u0@b.com
$bin $db user   $Nopass -s client-ca u1@b.com
$bin $db user   $Nopass -s client-ca u2@b.com

$bin $db list $Nopass

$bin $db export $Nopass -o s a.b.com
$bin $db export $Nopass -o c u0@b.com
