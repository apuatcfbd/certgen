package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	caCertPath := "./CAcert.pem"
	caKeyPath := "./CAkey.pem"

	//makeCA(caCertPath, caKeyPath)

	caCert, caKey := parseCA(caCertPath, caKeyPath)

	issueCertificateUsingCA(caCert, caKey)
}

func makeCA(caCertPath string, caKeyPath string) {

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	failIfErr(err, "")

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	failIfErr(err, "")

	// pem encode
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	writeToFile(caCertPath, caPEM, 0644)

	// encrypt
	encryptedCAPrivPemBytes, encErr := rsa.EncryptPKCS1v15(
		rand.Reader,
		&caPrivKey.PublicKey,
		[]byte("1234"),
	)
	failIfErr(encErr, "Key encryption failed")

	caPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	writeToFile(caKeyPath, caPrivKeyPEM, 0600)
}

func issueCertificateUsingCA(ca *x509.Certificate, caPrivKey *rsa.PrivateKey) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		DNSNames: []string{"printer.pp.com"},
		IPAddresses: []net.IP{
			net.IPv4(192, 168, 0, 121),
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	failIfErr(err, "")

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	failIfErr(err, "")

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	writeToFile("./cert.pem", certPEM, 0644)

	certPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	writeToFile("./key.pem", certPrivKeyPEM, 0600)
}

func parseCA(certPath string, keyPath string) (ca *x509.Certificate, caPrivKey *rsa.PrivateKey) {
	certBytes := readFromFile(certPath)
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		log.Fatalln("failed to decode PEM block containing certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	failIfErr(err, "CA certificate parse error")

	keyBytes := readFromFile(keyPath)
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		log.Fatalln("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	failIfErr(err, "CA private key parse error")

	return cert, key
}

func writeToFile(path string, content []byte, perm os.FileMode) {
	err := os.WriteFile(path, content, perm)
	failIfErr(err, "Failed to write "+path)
}

func readFromFile(path string) []byte {
	fileBytes, err := os.ReadFile(path)
	failIfErr(err, "File "+path+" read error: ")
	return fileBytes
}

func failIfErr(e error, prependMsg string) {
	if e != nil {
		log.Fatalf("%s, Error: %s \n", prependMsg, e.Error())
	}
}
