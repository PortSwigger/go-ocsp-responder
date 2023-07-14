// Dusted off and attempted to be modernised by SimonB @ PortSwigger.

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
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
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
	IndexModTime     time.Time
	CaCert           *x509.Certificate
	RespCert         *x509.Certificate
	NonceList        [][]byte
	Debug            bool
	Signer           crypto11.Signer
}

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
		IndexModTime:     time.Time{},
		CaCert:           nil,
		RespCert:         nil,
		NonceList:        nil,
		Debug:            false,
		Signer:           nil,
	}
}

// Creates an OCSP http handler and returns it
func (responder *OCSPResponder) makeHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		//log.Printf("INFO: Got %s request from %s", r.Method, r.RemoteAddr)
		if responder.Strict && r.Header.Get("Content-Type") != "application/ocsp-request" {
			log.Printf("ERROR: Strict mode requires correct Content-Type header")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		b := new(bytes.Buffer)
		switch r.Method {
		case "POST":
			b.ReadFrom(r.Body)
			log.Printf("INFO: Request from %v using %v on resource %v", r.Header.Get("X-Forwarded-For"), r.Method, r.URL.Path)
		case "GET":
			if r.URL.Path == "/healthcheck" {
				w.WriteHeader(200)
				w.Write([]byte("oakelydokely"))
				// Possibly too verbose, uncomment if needed.
				//if responder.Debug {
				//	log.Printf("INFO: Healthcheck acknowledged")
				//}
				return
			}
			//log.Printf("INFO: Request from %v using %v on resource %v", r.RemoteAddr, r.Method, r.URL.Path)
			// requests via the AWS ALB, use the x-fwd header instead.
			log.Printf("INFO: Request from %v using %v on resource %v", r.Header.Get("X-Forwarded-For"), r.Method, r.URL.Path)
			gd, err := base64.StdEncoding.DecodeString(r.URL.Path[1:])
			if err != nil {
				// tell the caller to go away.
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r := bytes.NewReader(gd)
			b.ReadFrom(r)
		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// parse request, verify, create response
		w.Header().Set("Content-Type", "application/ocsp-response")
		resp, err := responder.verify(b.Bytes())
		if err != nil {
			log.Printf("ERROR: %v", err)
			// technically we should return an ocsp error response. but this is probably fine
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		//log.Print("Writing response")
		w.Write(resp)
	}
}

// I only know of two types, but more can be added later
const (
	StatusValid   = "V"
	StatusRevoked = "R"
	StatusExpired = "E"
)

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
	RevokedOn          time.Time
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	SignatureAlgorithm x509.SignatureAlgorithm
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
	URIs               []*url.URL
	PubKey             []byte
	DerCert            []byte
}

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

// // takes a list of extensions and returns the nonce extension if it is present
// func checkForNonceExtension(exts []pkix.Extension) *pkix.Extension {
// 	nonce_oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
// 	for _, ext := range exts {
// 		if ext.Id.Equal(nonce_oid) {
// 			log.Println("Detected nonce extension")
// 			return &ext
// 		}
// 	}
// 	return nil
// }

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
	if err != nil {
		return record, err
	}
	svc := dynamodb.New(sess)

	// Ref: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Query.html#Query.FilterExpression
	filt := expression.Name("SerialNumber").Equal(expression.Value(sn.String()))

	// Ref: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ProjectionExpressions.html
	proj := expression.NamesList(
		expression.Name("Status"),
		expression.Name("Subject"),
		expression.Name("NotAfter"),
		expression.Name("NotBefore"),
		expression.Name("Environment"),
		expression.Name("RevokedOn"),
		expression.Name("SerialNumber"),
	)

	//expr, err := expression.NewBuilder().WithFilter(filt).WithProjection(proj).Build()
	expr, err := expression.NewBuilder().WithFilter(filt).WithProjection(proj).Build()
	if err != nil {
		return record, err
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
		return record, err
	}
	if len(output.Items) > 0 {
		//log.Printf("%#v", output.Items)
		// we should only ever have one record here unless we're cryptographically compromised.
		for _, i := range output.Items {
			err = dynamodbattribute.UnmarshalMap(i, &record)
			//log.Printf("DEBUG: record is %#v", record)
			return record, err
		}
	}
	return record, err
}

// takes the der encoded ocsp request, verifies it, and creates a response
func (responder *OCSPResponder) verify(rawreq []byte) ([]byte, error) {
	var status int
	var revokedAt time.Time

	// the original solution called 'ParseRequest' which returned 3 values, see here:
	// https://github.com/grimm-co/GOCSP-responder/blob/master/src/gocsp-responder/crypto/ocsp/ocsp.go#L411
	// TODO - we're using the upstream ocsp package
	req, err := ocsp.ParseRequest(rawreq)
	//req, exts, err := ocsp.ParseRequest(rawreq)

	if err != nil {
		log.Printf("ERROR: While trying to decode the request: (%v)", err)
		return nil, err
	}

	//make sure the request is valid
	if err := responder.verifyIssuer(req); err != nil {
		log.Println(err)
		return nil, err
	}

	ent, err := responder.getCertStatus(req.SerialNumber)
	if err != nil {
		log.Println(err)
		status = ocsp.Unknown
	} else {
		log.Printf("INFO: Found Status %v for Subject %v (SerialNumber: %v).  Cert expiry date is %v", ent.Status, ent.Subject, ent.SerialNumber, ent.NotAfter)
		if ent.Status == StatusRevoked {
			status = ocsp.Revoked
			revokedAt = ent.RevokedOn
		} else if ent.Status == StatusValid {
			status = ocsp.Good
		}
	}

	// // I feel the following are serious enough to be fatal errors...
	// ctx, err := crypto11.ConfigureFromFile(responder.Pkcs11ConfigFile)
	// if err != nil {
	// 	log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	// }
	// signers, err := ctx.FindAllKeyPairs()
	// if err != nil {
	// 	log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	// }

	// log.Printf("DEBUG: Signers is %v", signers)

	// // test we can use to sign and verify
	// data := []byte("mary had a little lamb")
	// h := sha256.New()
	// _, err = h.Write(data)
	// if err != nil {
	// 	log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	// }
	// hash := h.Sum([]byte{})

	// sig, err := signers[0].Sign(rand.Reader, hash, crypto.SHA256)
	// if err != nil {
	// 	log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	// }
	// err = rsa.VerifyPKCS1v15(signers[0].Public().(*rsa.PublicKey), crypto.SHA256, hash, sig)
	// if err != nil {
	// 	log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	// }

	//
	// check for nonce extension
	// TODO
	// var responseExtensions []pkix.Extension
	// TODO
	// nonce := checkForNonceExtension(exts)

	// // check if the nonce has been used before
	// if responder.NonceList == nil {
	// 	responder.NonceList = make([][]byte, 10)
	// }

	// // TODO
	// if nonce != nil {
	// 	for _, n := range self.NonceList {
	// 		if bytes.Compare(n, nonce.Value) == 0 {
	// 			return nil, errors.New("This nonce has already been used")
	// 		}
	// 	}

	// 	self.NonceList = append(self.NonceList, nonce.Value)
	// 	responseExtensions = append(responseExtensions, *nonce)
	// }

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
	resp, err := ocsp.CreateResponse(responder.CaCert, responder.RespCert, rtemplate, responder.Signer)
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
			log.Fatalf("Could not open log file %v (%v)", responder.LogFile, err)
		}
		defer lf.Close()
		log.SetOutput(lf)
	}

	//the certs should not change, so lets keep them in memory
	cacert, err := parseCertFile(responder.CaCertFile)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	respcert, err := parseCertFile(responder.RespCertFile)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}

	responder.CaCert = cacert
	responder.RespCert = respcert

	// now init the crypto
	ctx, err := crypto11.ConfigureFromFile(responder.Pkcs11ConfigFile)
	if err != nil {
		log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	}
	signers, err := ctx.FindAllKeyPairs()
	if err != nil {
		log.Fatalf("FATAL: Could not initialise PKCS11 provider (%v)", err)
	}

	log.Printf("DEBUG: Signers is %v", signers)
	log.Printf("DEBUG: Signers len is %v", len(signers))

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
		log.Fatalf("FATAL: Could not sign using PKCS11 provider (%v)", err)
	}
	err = rsa.VerifyPKCS1v15(signers[0].Public().(*rsa.PublicKey), crypto.SHA256, hash, sig)
	if err != nil {
		log.Fatalf("FATAL: Could not verify signature (%v)", err)
	}
	// ok, set the signer for future use
	responder.Signer = signers[0] // aws-kms-pkcs11 should only ever let us get 1 signer

	// get handler and serve
	handler := responder.makeHandler()
	http.HandleFunc("/", handler)
	listenOn := fmt.Sprintf("%s:%d", responder.Address, responder.Port)
	log.Printf("starting on %s", listenOn) //, responder.Ssl)
	http.ListenAndServe(listenOn, nil)
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Ldate | log.Lmicroseconds | log.Lshortfile)
	resp := Responder()
	flag.StringVar(&resp.IndexFile, "index", resp.IndexFile, "CA index filename")
	flag.StringVar(&resp.CaCertFile, "cacert", resp.CaCertFile, "CA certificate filename")
	flag.StringVar(&resp.RespCertFile, "mycert", resp.RespCertFile, "responder certificate filename")
	flag.StringVar(&resp.Pkcs11ConfigFile, "p11conf", resp.Pkcs11ConfigFile, "pkcs11 config filename")
	flag.StringVar(&resp.LogFile, "logfile", resp.LogFile, "file to log to")
	flag.StringVar(&resp.Address, "bind", resp.Address, "bind address")
	flag.IntVar(&resp.Port, "port", resp.Port, "listening port")
	//flag.BoolVar(&resp.Ssl, "ssl", resp.Ssl, "use SSL, this is not widely supported and not recommended")
	flag.BoolVar(&resp.Strict, "strict", resp.Strict, "require content type HTTP header")
	flag.BoolVar(&resp.LogToStdout, "stdout", resp.LogToStdout, "log to stdout, not the log file")
	flag.BoolVar(&resp.Debug, "debug", resp.Debug, "enable debugging info")
	flag.Parse()
	resp.Serve()
}
