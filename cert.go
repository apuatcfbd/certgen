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

func certGenCA(caKey *rsa.PrivateKey, cfg *caConfig) (cert *x509.Certificate, err error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(int64(cfg.Serial)),
		Subject: pkix.Name{
			Organization:  []string{cfg.Info.Organization},
			Country:       []string{cfg.Info.Country},
			Locality:      []string{cfg.Info.Locality},
			StreetAddress: []string{cfg.Info.StreetAddress},
			PostalCode:    []string{cfg.Info.PostalCode},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(cfg.ExpiryYears, 0, 0),
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
		return
	}

	cert, parseErr := x509.ParseCertificate(caBytes)
	if parseErr != nil {
		err = parseErr
	}

	return
}

func certSaveToFile(cert *x509.Certificate, path string) error {
	// save DER
	writeToFile(path+".crt", cert.Raw, 0600)

	// save PEM
	certPem := certPemEncode(cert)
	writeToFile(path+".pem", certPem, 0600)

	return nil
}

func certGetFromFile(path string) (cert *x509.Certificate, err error) {
	certPemBytes := readFromFile(path)
	certBlock, _ := pem.Decode(certPemBytes)
	if certBlock == nil || certBlock.Type != pemTypeCert {
		return nil, errors.New("failed to decode PEM block containing certificate from " + path)
	}

	cert, certParseErr := x509.ParseCertificate(certBlock.Bytes)
	if certParseErr != nil {
		return nil, errors.New("failed to parse certificate from " + path)
	}

	return cert, nil
}

func certPemEncode(cert *x509.Certificate) (certPem []byte) {
	pemBlock := &pem.Block{
		Type:  pemTypeCert,
		Bytes: cert.Raw,
	}
	certPem = pem.EncodeToMemory(pemBlock)
	return certPem
}

func certGenServer(
	ca *x509.Certificate,
	caKey *rsa.PrivateKey,
	serverKey *rsa.PrivateKey,
	cfg *serverConfig,
) (serverCert *x509.Certificate, err error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(cfg.Serial)),
		PublicKey:    serverKey.PublicKey,
		Subject: pkix.Name{
			Organization:  []string{cfg.Info.Organization},
			Country:       []string{cfg.Info.Country},
			Locality:      []string{cfg.Info.Locality},
			StreetAddress: []string{cfg.Info.StreetAddress},
			PostalCode:    []string{cfg.Info.PostalCode},
			CommonName:    cfg.Info.CommonName,
		},
		DNSNames:    []string{cfg.Info.CommonName},
		IPAddresses: []net.IP{net.ParseIP(cfg.IpAddress)},
		IsCA:        false,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(cfg.ExpiryYears, 0, 0),
		//SubjectKeyId:   ca.SubjectKeyId,
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
		return
	}

	serverCert, certParseErr := x509.ParseCertificate(certBytes)
	if certParseErr != nil {
		err = certParseErr
	}

	return
}

func certPKCS12Encode(
	cert *x509.Certificate,
	certKey *rsa.PrivateKey,
	password string,
) (pfxBytes []byte, err error) {
	//pfxBytes, err := pkcs12.Encode(rand.Reader, certKey, cert, []*x509.Certificate{}, password)
	//pfxBytes, err := pkcs12.LegacyRC2.Encode(certKey, cert, []*x509.Certificate{}, password)
	pfxBytes, err = pkcs12.Modern.WithRand(rand.Reader).Encode(certKey, cert, nil, password)
	if err != nil {
		return nil, err
	}
	return pfxBytes, nil
}

// pfxCert must be DER encoded
func certPKCS12Decode(pfxCert []byte, password string) (pKey interface{}, cert *x509.Certificate, err error) {
	pKey, cert, err = pkcs12.Decode(pfxCert, password)
	if err != nil {
		return nil, nil, err
	}
	return pKey, cert, nil
}

func parseCA2(certPath string, keyPath string) (ca *x509.Certificate, caPrivKey *rsa.PrivateKey) {
	certBytes := readFromFile(certPath)
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil || certBlock.Type != pemTypeCert {
		log.Fatalln("failed to decode PEM block containing certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	failIfErr(err, "CA certificate parse error")

	keyBytes := readFromFile(keyPath)
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != pemTypePrivateKey {
		log.Fatalln("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	failIfErr(err, "CA private key parse error")

	return cert, key
}
