package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ThalesIgnite/crypto11"
)

type Config struct {
	Path       string `json:"P11Path"`
	TokenLabel string `json:"P11TokenLabel"`
	Pin        string `json:"P11Pin"`
	SlotNumber int    `json:"P11Slot"`
}

var config Config
var flFqdn, flConfig, flPubKey string
var flDebug bool

func main() {
	flag.StringVar(&flFqdn, "fqdn", "localhost", "hostname for the csr")
	flag.StringVar(&flPubKey, "pubkey", "", "filename to pass in a pem formatted rsa key from aws kms or similar")
	flag.BoolVar(&flDebug, "debug", false, "show more stuff about what's happening.")
	// config
	flag.StringVar(&flConfig, "config", "config.json", "override the default config file to be used.")
	flag.Parse()

	confJson, err := os.ReadFile(flConfig)
	if err != nil {
		log.Fatalf("FATAL: Couldn't open config file config.json (%v)", err)
	}
	err = json.Unmarshal(confJson, &config)
	if err != nil {
		log.Fatalf("FATAL: malformed config file config.json (%v)", err)
	}

	pubKeyPem, err := os.ReadFile(flPubKey)
	if err != nil {
		log.Fatalf("FATAL: I need the subjects public key in the file %v (in PEM format) (%v)", flPubKey, err)
	}
	block, rest := pem.Decode(pubKeyPem)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Got a %T, with remaining data: %q", pub, rest)

	// now find the Signer...
	signer, err := initPkcs11(pub.(*rsa.PublicKey))
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}

	// CertSquirt ignores pretty much all of this
	subj := pkix.Name{
		CommonName: flFqdn,
	}
	rawSubj := subj.ToRDNSequence()

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	template.DNSNames = append(template.DNSNames, flFqdn)

	log.Printf("DEBUG: Template is %#v", template)

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		log.Printf("Error: %v", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

}

func initPkcs11(pubkey *rsa.PublicKey) (signer crypto11.Signer, err error) {
	var flDebug = true
	if flDebug {
		log.Printf("DEBUG: init called with pubkey of type %T", pubkey)
	}
	// depending on the pkcs11 provider we need to pass these in differently.
	// For KMS and some others , we need to find the key via the Token Label,
	// but the YubiKey and others, we need to locate the token via the slot.
	//
	// crypto11.Config
	var p11Config crypto11.Config
	if flDebug {
		log.Printf("Attempting to configure provider with these values: %#v, %#v, %#v, %#v", config.Path, config.Pin, config.TokenLabel, config.SlotNumber)
	}
	if config.TokenLabel != "" {
		p11Config = crypto11.Config{
			Path: config.Path,
			Pin:  config.Pin,
			//SlotNumber: &config.SlotNumber,
			TokenLabel: config.TokenLabel,
		}
	} else {
		p11Config = crypto11.Config{
			Path:       config.Path,
			Pin:        config.Pin,
			SlotNumber: &config.SlotNumber,
			//TokenLabel: config.TokenLabel,
		}
	}

	if flDebug {
		log.Printf("DEBUG: P11Config is %#v", p11Config)
	}
	ctx, err := crypto11.Configure(&p11Config)
	if err != nil {
		return signer, err
	}
	if flDebug {
		log.Printf("DEBUG: crypto11.Context is : %#v", ctx)
	}
	signers, err := ctx.FindAllKeyPairs()
	if err != nil {
		return signer, err
	}
	if flDebug {
		log.Printf("Signers are: %#v", signers)
	}
	for x, y := range signers {
		if flDebug {
			log.Printf("Signer is a %T %#v", y.Public(), y)
		}
		switch y.Public().(type) {
		case *rsa.PublicKey:
			//var signingkey *rsa.PublicKey = y.Public().(*rsa.PublicKey)
			if pubkey.Equal(y.Public()) {
				//if signingkey.Equal(pubkey.(rsa.PublicKey)) {
				return signers[x], nil
			} else {
				log.Printf("INFO: public key mismatch, checking next key")
			}
		default:
			// do nowt.
		}
	}
	return signer, errors.New("something weird happened.  please file an issue at https://github.com/PortSwigger/certsquirt/issues")
}