package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/pkcs12"

	"github.com/ferlonas/hpkp"
)

func main() {
	var err error

	serverPtr := flag.String("server", "", "server to inspect (ex: github.com:443)")
	filePtr := flag.String("file", "", "path to PEM encoded certificate")
	clientP12 := flag.String("client-cert", "", "path to PKCS12 encoded client certificate (only for server inspection)")
	clientKey := flag.String("client-key", "", "key required for PKCS12 client certificate (only if required")

	flag.Parse()

	if *filePtr != "" {
		err = fromFile(*filePtr)
	}

	if err != nil {
		log.Fatal(err)
	}

	if *serverPtr != "" {
		err = fromServer(*serverPtr, *clientP12, *clientKey)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func fromServer(server, cCertPath, cCertKey string) error {
	ctx := context.Background()
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if cCertPath != "" {
		cert, err := loadPKCS12(cCertPath, cCertKey)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.Certificates = []tls.Certificate{
			*cert,
		}
	}

	c, err := (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, "tcp", server)
	if err != nil {
		return err
	}
	// do a normal dial, address isn't in hpkp cache
	conn := tls.Client(c, tlsConfig)

	if err != nil {
		return err
	}

	for _, cert := range conn.ConnectionState().PeerCertificates {
		fmt.Printf("%s", hpkp.Fingerprint(cert))
		if cert.IsCA {
			fmt.Printf(" (CA)")
		}
		fmt.Println()
	}

	return nil
}

func fromFile(path string) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var block *pem.Block

	for len(contents) > 0 {
		block, contents = pem.Decode(contents)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", hpkp.Fingerprint(cert))
		if cert.IsCA {
			fmt.Printf(" (CA)")
		}
		fmt.Println()
	}

	return nil
}

func loadPKCS12(path, key string) (*tls.Certificate, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", path, err)
	}

	blocks, err := pkcs12.ToPEM(bytes, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %v", err)
	}

	var pemData []byte
	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return nil, fmt.Errorf("failed to create X509KeyPair: %v", err)
	}

	return &cert, nil
}
