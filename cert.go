package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"software.sslmate.com/src/go-pkcs12"
	"time"
)

func certMain() {
	caCertPath := certPath + "CAcert.pem"
	caKeyPath := certPath + "CAkey.pem"

	makeCA(caCertPath, caKeyPath)

	caCert, caKey := parseCA(caCertPath, caKeyPath)

	issueCertificateUsingCA(caCert, caKey)
}

func certGenCA(caKey *rsa.PrivateKey) (cert *x509.Certificate, certBytes []byte, err error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization:  []string{"Snebtaf"},
			Country:       []string{"UK"},
			Locality:      []string{"London"},
			StreetAddress: []string{"Bricklane"},
			PostalCode:    []string{"E1 6QL"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	cert, parseErr := x509.ParseCertificate(caBytes)
	if parseErr != nil {
		return nil, nil, parseErr
	}

	return cert, caBytes, nil
}

func certSaveToFile(certBytes []byte, path string) error {
	// save DER
	writeToFile(path+".crt", certBytes, 0600)

	// save PEM
	certPem := certPemEncode(certBytes)
	writeToFile(path+".pem", certPem, 0600)

	return nil
}

func certGetFromFile(path string) (cert *x509.Certificate, err error) {
	certPemBytes := readFromFile(path)
	certBlock, _ := pem.Decode(certPemBytes)
	if certBlock == nil || certBlock.Type != pemCertType {
		return nil, errors.New("failed to decode PEM block containing certificate from " + path)
	}

	cert, certParseErr := x509.ParseCertificate(certBlock.Bytes)
	if certParseErr != nil {
		return nil, errors.New("failed to parse certificate from " + path)
	}

	return cert, nil
}

func certPemEncode(certBytes []byte) (certPem []byte) {
	pemBlock := &pem.Block{
		Type:  pemCertType,
		Bytes: certBytes,
	}
	certPem = pem.EncodeToMemory(pemBlock)
	return certPem
}

func certGenServer(
	ca *x509.Certificate,
	caKey *rsa.PrivateKey,
	serverKey *rsa.PrivateKey,
) (serverCert *x509.Certificate, serverCertBytes []byte, err error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		PublicKey:    serverKey.PublicKey,
		Subject: pkix.Name{
			Organization: []string{"Ordering2online"},
			Country:      []string{"UK"},
			Locality:     []string{"London"},
			//StreetAddress: []string{"Golden Gate Bridge"},
			//PostalCode:    []string{"94016"},
			CommonName: "printer.pp.com",
		},
		DNSNames:       []string{"printer.pp.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.0.121")},
		IsCA:           false,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(5, 0, 0),
		SubjectKeyId:   ca.SubjectKeyId,
		AuthorityKeyId: ca.AuthorityKeyId,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageContentCommitment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	cert, certParseErr := x509.ParseCertificate(certBytes)
	if certParseErr != nil {
		return nil, nil, certParseErr
	}

	return cert, certBytes, nil
}

func certPKCS12Encode(
	cert *x509.Certificate,
	certKey *rsa.PrivateKey,
	caCert *x509.Certificate,
	password string,
) (pfxBytes []byte, err error) {
	//pfxBytes, err := pkcs12.Encode(rand.Reader, certKey, cert, []*x509.Certificate{caCert}, password)
	//pfxBytes, err := pkcs12.LegacyRC2.Encode(certKey, cert, []*x509.Certificate{caCert}, password)
	pfxBytes, err = pkcs12.Modern.WithRand(rand.Reader).Encode(certKey, cert, []*x509.Certificate{caCert}, password)
	if err != nil {
		return nil, err
	}
	return pfxBytes, nil
}

// pfxCert must be DER encoded
func certPKCS12Decode(pfxCert []byte, password string) (pKey interface{}, cert *x509.Certificate, caCerts []*x509.Certificate, err error) {
	pKey, cert, caCerts, err = pkcs12.DecodeChain(pfxCert, password)
	if err != nil {
		return nil, nil, nil, err
	}
	return pKey, cert, caCerts, nil
}

func parseCA2(certPath string, keyPath string) (ca *x509.Certificate, caPrivKey *rsa.PrivateKey) {
	certBytes := readFromFile(certPath)
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil || certBlock.Type != pemCertType {
		log.Fatalln("failed to decode PEM block containing certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	failIfErr(err, "CA certificate parse error")

	keyBytes := readFromFile(keyPath)
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != pemPrivateKeyType {
		log.Fatalln("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	failIfErr(err, "CA private key parse error")

	return cert, key
}
