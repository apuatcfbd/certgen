package main

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	pemTypeCert        = "CERTIFICATE"
	pemTypePrivateKey  = "RSA PRIVATE KEY"
	pemTypePublicKey   = "RSA PUBLIC KEY"
	pemTypeCertRequest = "CERTIFICATE REQUEST"
	keyBits            = 2048
	certPath           = "./certs/"
)

func main() {
	input, err := readUserInput(
		`What to do?
1. Generate sample config
2. Generate Key's using config
`)
	failIfErr(err, "Failed to read your input")

	input = strings.ToLower(input)

	switch input {
	case "1":
		generateEmptyConfigFile()
	case "2":
		c := config{}
		c.Parse()
		makeCerts(&c)
	default:
		log.Println("Incorrect input!")
	}

}

func makeCerts(c *config) {

	// warn if project dir exists
	if exists, _ := isPathExist(c.ProjectInfo.Path); exists {
		input, err := readUserInput("Existing server certificates will be replaced by new one, continue? [y/N]")
		failIfErr(err, "Failed to read your input")

		input = strings.ToLower(input)
		if input != "y" {
			fmt.Println("Cancelled!")
			return
		}
	} else {
		// create project dir
		er := os.Mkdir(c.ProjectInfo.Path, 0750)
		failIfErr(er, "Project dir creation err")
	}

	log.Println("Creating certificate for project:", c.ProjectInfo.Name)

	// get or make CA
	caKey, caCert := getCA(c)

	// get server cert
	getSrvCert(c, caKey, caCert)

}

func getCA(c *config) (*rsa.PrivateKey, *x509.Certificate) {
	// get key
	shouldLoad := true
	keyPath := c.Ca.Key

	if keyPath == "" {
		keyPath = c.ProjectInfo.CaKey
		shouldLoad = false
	}

	key := loadOrGenKey(keyPath, shouldLoad)

	// get cert

	if c.Ca.Cert != "" {
		cert, err := certGetFromFile(c.Ca.Cert)
		failIfErr(err, "CA certificate load err")

		log.Println("Using CA:", c.Ca.Cert)
		return key, cert
	}

	cert, err := certGenCA(key, &c.Ca)
	failIfErr(err, "Ca certificate generation err")

	certSaveErr := certSaveToFile(cert, c.ProjectInfo.CaCertName)
	failIfErr(certSaveErr, "Ca certificate save err")

	log.Println("Generated CA:", c.ProjectInfo.CaCertName, ".{crt,pem}")
	return key, cert
}

func getSrvCert(c *config, caKey *rsa.PrivateKey, caCert *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate) {
	// get key
	shouldLoad := true
	keyPath := c.Server.Key

	if keyPath == "" {
		keyPath = c.ProjectInfo.SrvKey
		shouldLoad = false
	}

	key := loadOrGenKey(keyPath, shouldLoad)

	// get cert

	cert, err := certGenServer(caCert, caKey, key, &c.Server)
	failIfErr(err, "Server certificate generation err")

	certSaveErr := certSaveToFile(cert, c.ProjectInfo.SrvCertName)
	failIfErr(certSaveErr, "Server certificate save err")
	log.Println("Generated Server Cert:", c.ProjectInfo.SrvCertName+".{crt,pem}")

	// save pfx
	pfxBytes, serverPfxSaveErr := certPKCS12Encode(cert, key, c.Server.Password)
	failIfErr(serverPfxSaveErr, "Encrypted server certificate save err")
	writeToFile(c.ProjectInfo.SrvCertPfx, pfxBytes, 0600)

	log.Println("Generated Encrypted Server Cert (using provided password):", c.ProjectInfo.SrvCertName+".pfx")
	return key, cert
}

// loads or generates & saves key to specified path
func loadOrGenKey(keyPath string, loadKey bool) *rsa.PrivateKey {
	if loadKey {
		loadedKey, err := keyGetFromFile(keyPath)
		failIfErr(err, "Key load err")

		log.Println("Using key:", keyPath)
		return loadedKey
	}

	newKey, err := keyGen()
	failIfErr(err, "Key generation err")

	keySaveErr := keySaveToFile(newKey, keyPath)
	failIfErr(keySaveErr, "Key save err")

	log.Println("Generated key:", keyPath)
	return newKey
}
