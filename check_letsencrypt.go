package main

import (
	"fmt"
	"crypto/tls"
	"net"
	"os"
	"io"
	"bufio"
	"time"
)

type CLI struct {
	outStream, errStream io.Writer
}

const letsencrypt_ca string = "Let's Encrypt Authority X3"

func check(host string) (isLE bool, err error) {
	dialer := &net.Dialer {
		Timeout: 5000 * time.Millisecond,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", host + ":443", nil)

	if err != nil {
		return false, err
	}
	defer conn.Close()

	for _, certificate := range conn.ConnectionState().PeerCertificates {
		if certificate.IsCA && letsencrypt_ca == certificate.Subject.CommonName {
			return true, nil
		}
	}
	return false, nil
}

func (c *CLI) Run(args []string) int {
	fp := os.Stdin

	scanner := bufio.NewScanner(fp)
	err_domain_list := []string{}

	for scanner.Scan() {
		domain := scanner.Text()
		isLE, err := check(domain)
		if err != nil {
			fmt.Fprintln(c.errStream, err)
			err_domain_list = append(err_domain_list, domain)
		}
		if isLE {
			fmt.Fprintln(c.outStream, domain)
		}
	}
	if len(err_domain_list) > 0 {
		fmt.Fprintln(c.errStream, "Error List:")
		for _, err_domain := range err_domain_list {
			fmt.Fprintln(c.errStream, err_domain)
		}
	}

	return 0
}

func main() {
	cli := &CLI{outStream: os.Stdout, errStream: os.Stderr}
	os.Exit(cli.Run(os.Args))
}
