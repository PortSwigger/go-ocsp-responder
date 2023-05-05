// Dusted off and attempted to be Modernised by SimonB @ PortSwigger.
//
// Copyright 2016 SMFS Inc. DBA GRIMM. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Implementation of an OCSP responder defined by RFC 6960

// Copyright 2016 SMFS Inc DBA GRIMM. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"golang.org/x/crypto/ocsp"
)

type OCSPResponder struct {
	IndexFile        string
	Pkcs11ConfigFile string
	RespCertFile     string
	CaCertFile       string
	LogFile          string
	LogToStdout      bool
	Strict           bool
	Port             int
	Address          string
	//IndexEntries     []IndexEntry
	IndexModTime time.Time
	CaCert       *x509.Certificate
	RespCert     *x509.Certificate
	NonceList    [][]byte
}

// I decided on these defaults based on what I was using
func Responder() *OCSPResponder {
	return &OCSPResponder{
		IndexFile:        "index.txt",
		Pkcs11ConfigFile: "pkcs11-config.json",
		RespCertFile:     "responder.crt",
		CaCertFile:       "ca.crt",
		LogFile:          "gocsp-responder.log",
		LogToStdout:      false,
		Strict:           false,
		Port:             8888,
		Address:          "",
		//Ssl:              false,
		//IndexEntries:     nil,
		IndexModTime: time.Time{},
		CaCert:       nil,
		RespCert:     nil,
		NonceList:    nil,
	}
}

// Creates an OCSP http handler and returns it
func (responder *OCSPResponder) makeHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Got %s request from %s", r.Method, r.RemoteAddr)
		if responder.Strict && r.Header.Get("Content-Type") != "application/ocsp-request" {
			log.Println("Strict mode requires correct Content-Type header")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		b := new(bytes.Buffer)
		switch r.Method {
		case "POST":
			b.ReadFrom(r.Body)
		case "GET":
			log.Println(r.URL.Path)
			gd, err := base64.StdEncoding.DecodeString(r.URL.Path[1:])
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r := bytes.NewReader(gd)
			b.ReadFrom(r)
		default:
			log.Println("Unsupported request method")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// parse request, verify, create response
		w.Header().Set("Content-Type", "application/ocsp-response")
		resp, err := responder.verify(b.Bytes())
		if err != nil {
			log.Print(err)
			// technically we should return an ocsp error response. but this is probably fine
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Print("Writing response")
		w.Write(resp)
	}
}

// I only know of two types, but more can be added later
const (
	StatusValid   = "V"
	StatusRevoked = "R"
	StatusExpired = "E"
)

// // TODO - implement dynamodb lookups instead.
// type CertStatus struct {
// 	Status            string
// 	Serial            *big.Int
// 	IssueTime         time.Time
// 	RevocationTime    time.Time
// 	DistinguishedName string
// }

// maps across to github.com/PortSwigger/certsquirt
// DynamoDB records (https://github.com/PortSwigger/certsquirt/blob/main/db.go#L26)
type x509Record struct {
	Status             string
	Requester          string
	SerialNumber       string
	Issuer             string
	Subject            string
	NotBefore          time.Time
	NotAfter           time.Time
	RevocationTime     time.Time
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	SignatureAlgorithm x509.SignatureAlgorithm
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
	URIs               []*url.URL
	PubKey             []byte
	DerCert            []byte
}

/*
// function to parse the index file
func (responder *OCSPResponder) parseIndex() error {
	var t string = "060102150405Z"
	finfo, err := os.Stat(responder.IndexFile)
	if err == nil {
		// if the file modtime has changed, then reload the index file
		if finfo.ModTime().After(responder.IndexModTime) {
			log.Print("Index has changed. Updating")
			responder.IndexModTime = finfo.ModTime()
			// clear index entries
			responder.IndexEntries = responder.IndexEntries[:0]
		} else {
			// the index has not changed. just return
			return nil
		}
	} else {
		return err
	}

	// open and parse the index file
	if file, err := os.Open(responder.IndexFile); err == nil {
		defer file.Close()
		s := bufio.NewScanner(file)
		for s.Scan() {
			var ie IndexEntry
			ln := strings.Fields(s.Text())
			ie.Status = []byte(ln[0])[0]
			ie.IssueTime, _ = time.Parse(t, ln[1])
			if ie.Status == StatusValid {
				ie.Serial, _ = new(big.Int).SetString(ln[2], 16)
				ie.DistinguishedName = ln[4]
				ie.RevocationTime = time.Time{} //doesn't matter
			} else if ie.Status == StatusRevoked {
				ie.Serial, _ = new(big.Int).SetString(ln[3], 16)
				ie.DistinguishedName = ln[5]
				ie.RevocationTime, _ = time.Parse(t, ln[2])
			} else {
				// invalid status or bad line. just carry on
				continue
			}
			responder.IndexEntries = append(responder.IndexEntries, ie)
		}
	} else {
		return err
	}
	return nil
}
*/
/*
// updates the index if necessary and then searches for the given index in the
// index list
func (responder *OCSPResponder) getIndexEntry(s *big.Int) (*IndexEntry, error) {
	log.Printf("Looking for serial 0x%x", s)
	if err := responder.parseIndex(); err != nil {
		return nil, err
	}
	for _, ent := range responder.IndexEntries {
		if ent.Serial.Cmp(s) == 0 {
			return &ent, nil
		}
	}
	return nil, fmt.Errorf("serial 0x%x not found", s)
}
*/
// parses a pem encoded x509 certificate
func parseCertFile(filename string) (*x509.Certificate, error) {
	ct, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(ct)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// // parses a PEM encoded PKCS8 private key (RSA only)
// func parseKeyFile(filename string) (interface{}, error) {
// 	kt, err := os.ReadFile(filename)
// 	if err != nil {
// 		return nil, err
// 	}
// 	block, _ := pem.Decode(kt)
// 	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return key, nil
// }

// takes a list of extensions and returns the nonce extension if it is present
func checkForNonceExtension(exts []pkix.Extension) *pkix.Extension {
	nonce_oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	for _, ext := range exts {
		if ext.Id.Equal(nonce_oid) {
			log.Println("Detected nonce extension")
			return &ext
		}
	}
	return nil
}

func (responder *OCSPResponder) verifyIssuer(req *ocsp.Request) error {
	h := req.HashAlgorithm.New()
	h.Write(responder.CaCert.RawSubject)
	if !bytes.Equal(h.Sum(nil), req.IssuerNameHash) {
		return errors.New("issuer name does not match")
	}
	h.Reset()
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(responder.CaCert.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return err
	}
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	if !bytes.Equal(h.Sum(nil), req.IssuerKeyHash) {
		return errors.New("issuer key hash does not match")
	}
	return nil
}

func (responder *OCSPResponder) getCertStatus(sn *big.Int) (record x509Record, err error) {
	tableName, ok := os.LookupEnv("DB_TABLE_NAME")
	if !ok {
		log.Fatalf("FATAL: Cannot retrieve $DB_TABLE_NAME")
	}
	awsregion, _ := os.LookupEnv("AWS_REGION")
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsregion)},
	)
	svc := dynamodb.New(sess)

	// Ref: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Query.html#Query.FilterExpression
	filt := expression.Name("Revoked").Equal(expression.Value(false))

	// Ref: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ProjectionExpressions.html
	proj := expression.NamesList(
		expression.Name("RevocationTime"),
		expression.Name("AccessKey"),
		expression.Name("Username"),
		expression.Name("Environment"),
	)

	expr, err := expression.NewBuilder().WithFilter(filt).WithProjection(proj).Build()
	if err != nil {
		log.Fatalf("FATAL: Got error building expression: %s", err)
	}

	// Build the query input parameters
	params := &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 aws.String(tableName),
	}

	// Make the DynamoDB Query initial API call
	output, err := svc.Scan(params)
	if err != nil {
		log.Fatalf("FATAL: Query API call failed: %s", err)
	}
	if len(output.Items) > 0 {
	}
	return record, err
}

// takes the der encoded ocsp request, verifies it, and creates a response
func (responder *OCSPResponder) verify(rawreq []byte) ([]byte, error) {
	var status int
	var revokedAt time.Time

	// parse the request
	// TODO - we're using the upstream ocsp package
	req, err := ocsp.ParseRequest(rawreq)
	//req, exts, err := ocsp.ParseRequest(rawreq)

	if err != nil {
		log.Println(err)
		return nil, err
	}

	//make sure the request is valid
	if err := responder.verifyIssuer(req); err != nil {
		log.Println(err)
		return nil, err
	}

	// get the index entry, if it exists
	ent, err := responder.getCertStatus(req.SerialNumber)
	if err != nil {
		log.Println(err)
		status = ocsp.Unknown
	} else {
		log.Printf("Found entry %+v", ent)
		if ent.Status == StatusRevoked {
			log.Print("This certificate is revoked")
			status = ocsp.Revoked
			revokedAt = ent.RevocationTime
		} else if ent.Status == StatusValid {
			log.Print("This certificate is valid")
			status = ocsp.Good
		}
	}
	ctx, err := crypto11.ConfigureFromFile(responder.Pkcs11ConfigFile)
	if err != nil {
		log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	}
	signers, err := ctx.FindAllKeyPairs()
	if err != nil {
		log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	}
	// test we can use to sign and verify
	data := []byte("mary had a little lamb")
	h := sha256.New()
	_, err = h.Write(data)
	if err != nil {
		log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	}
	hash := h.Sum([]byte{})

	sig, err := signers[0].Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	}
	err = rsa.VerifyPKCS1v15(signers[0].Public().(*rsa.PublicKey), crypto.SHA256, hash, sig)
	if err != nil {
		log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	}

	/*
		// parse key file
		// perhaps I should zero this out after use
		keyi, err := parseKeyFile(responder.RespKeyFile)
		if err != nil {
			return nil, err
		}
		key, ok := keyi.(crypto.Signer)
		if !ok {
			return nil, errors.New("could not make key a signer")
		}
	*/

	// check for nonce extension
	// TODO
	// var responseExtensions []pkix.Extension
	// TODO
	//nonce := checkForNonceExtension(exts)

	// check if the nonce has been used before
	if responder.NonceList == nil {
		responder.NonceList = make([][]byte, 10)
	}

	/* TODO
	if nonce != nil {
		for _, n := range self.NonceList {
			if bytes.Compare(n, nonce.Value) == 0 {
				return nil, errors.New("This nonce has already been used")
			}
		}

		self.NonceList = append(self.NonceList, nonce.Value)
		responseExtensions = append(responseExtensions, *nonce)
	}
	*/

	// construct response template
	rtemplate := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		Certificate:      responder.RespCert,
		RevocationReason: ocsp.Unspecified,
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revokedAt,
		ThisUpdate:       time.Now().AddDate(0, 0, -1).UTC(),
		//adding 1 day after the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		NextUpdate: time.Now().AddDate(0, 0, 1).UTC(),
		// Extensions: exts, // TODO
	}

	// make a response to return
	resp, err := ocsp.CreateResponse(responder.CaCert, responder.RespCert, rtemplate, signers[0])
	if err != nil {
		return nil, err
	}

	return resp, err
}

// setup an ocsp server instance with configured values
func (responder *OCSPResponder) Serve() error {
	// setup logging
	if !responder.LogToStdout {
		lf, err := os.OpenFile(responder.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0664)
		if err != nil {
			log.Fatal("Could not open log file " + responder.LogFile)
		}
		defer lf.Close()
		log.SetOutput(lf)
	}

	//the certs should not change, so lets keep them in memory
	cacert, err := parseCertFile(responder.CaCertFile)
	if err != nil {
		log.Fatal(err)
		return err
	}
	respcert, err := parseCertFile(responder.RespCertFile)
	if err != nil {
		log.Fatal(err)
		return err
	}

	responder.CaCert = cacert
	responder.RespCert = respcert

	// get handler and serve
	handler := responder.makeHandler()
	http.HandleFunc("/", handler)
	listenOn := fmt.Sprintf("%s:%d", responder.Address, responder.Port)
	log.Printf("GOCSP-Responder starting on %s", listenOn) //, responder.Ssl)
	http.ListenAndServe(listenOn, nil)
	return nil
}

func main() {
	resp := Responder()
	flag.StringVar(&resp.IndexFile, "index", resp.IndexFile, "CA index filename")
	flag.StringVar(&resp.CaCertFile, "cacert", resp.CaCertFile, "CA certificate filename")
	flag.StringVar(&resp.RespCertFile, "rcert", resp.RespCertFile, "responder certificate filename")
	flag.StringVar(&resp.Pkcs11ConfigFile, "p11conf", resp.Pkcs11ConfigFile, "pkcs11 config filename")
	flag.StringVar(&resp.LogFile, "logfile", resp.LogFile, "file to log to")
	flag.StringVar(&resp.Address, "bind", resp.Address, "bind address")
	flag.IntVar(&resp.Port, "port", resp.Port, "listening port")
	//flag.BoolVar(&resp.Ssl, "ssl", resp.Ssl, "use SSL, this is not widely supported and not recommended")
	flag.BoolVar(&resp.Strict, "strict", resp.Strict, "require content type HTTP header")
	flag.BoolVar(&resp.LogToStdout, "stdout", resp.LogToStdout, "log to stdout, not the log file")
	flag.Parse()
	resp.Serve()
}
