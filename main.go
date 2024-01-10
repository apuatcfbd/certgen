package main

import (
	"crypto/rsa"
	"crypto/x509"
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
	////generateEmptyConfigFile()
	//c := config{}
	//c.Parse()
	//fmt.Printf("Config %#v \n", c)

	cfg := config{}
	cfg.Parse()

	makeCerts(&cfg)
}

func makeCerts(cfg *config) {

	// get or make CA
	caKey, caCert := getCA(cfg)

	// get server cert
	srvKey, srvCert := getSrvCert(cfg, caKey, caCert)

	//// gen CA key
	//caKey := genKey()
	//caKeySaveErr := keySaveToFile(caKey, certPath+"ca_key.pem")
	//failIfErr(caKeySaveErr, "")
	//
	//// get CA Root cert
	//caCert, caCertGenErr := certGenCA(caKey)
	//failIfErr(caCertGenErr, "")
	//caCertSaveErr := certSaveToFile(caCert, certPath+"ca_cert")
	//failIfErr(caCertSaveErr, "")

	// issue server cert using CA

	// gen server key
	serverKey := genKey()
	serverKeySaveErr := keySaveToFile(serverKey, certPath+"server_key.pem")
	failIfErr(serverKeySaveErr, "")

	// gen server cert
	serverCert, serverCertGenErr := certGenServer(caCert, caKey, serverKey)
	failIfErr(serverCertGenErr, "")
	serverCertSaveErr := certSaveToFile(serverCert, certPath+"server_cert")
	failIfErr(serverCertSaveErr, "")

	// gen server pfx
	pfxBytes, serverPfxSaveErr := certPKCS12Encode(serverCert, serverKey, "1234")
	failIfErr(serverPfxSaveErr, "")
	writeToFile(certPath+"server_cert.pfx", pfxBytes, 0600)
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
		return key, cert
	}

	cert, err := certGenCA(key, &c.Ca)
	failIfErr(err, "Ca certificate generation err")

	certSaveErr := certSaveToFile(cert, c.ProjectInfo.CaCert)
	failIfErr(certSaveErr, "Ca certificate save err")

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

	certSaveErr := certSaveToFile(cert, c.ProjectInfo.SrvCertPem)
	failIfErr(certSaveErr, "Server certificate save err")

	// save pfx
	pfxBytes, serverPfxSaveErr := certPKCS12Encode(cert, key, c.Server.Password)
	failIfErr(serverPfxSaveErr, "Encrypted server certificate save err")
	writeToFile(c.ProjectInfo.SrvCertPfx, pfxBytes, 0600)

	return key, cert
}

// loads or generates & saves key to specified path
func loadOrGenKey(keyPath string, loadKey bool) *rsa.PrivateKey {
	if loadKey {
		loadedKey, err := keyGetFromFile(keyPath)
		failIfErr(err, "Key load err")
		return loadedKey
	}

	newKey, err := keyGen()
	failIfErr(err, "Key generation err")

	keySaveErr := keySaveToFile(newKey, keyPath)
	failIfErr(keySaveErr, "Key save err")
	return newKey
}
