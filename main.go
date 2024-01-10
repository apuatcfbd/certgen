package main

import "crypto/rsa"

const (
	pemCertType       = "CERTIFICATE"
	pemPrivateKeyType = "RSA PRIVATE KEY"
	pemPublicKeyType  = "RSA PUBLIC KEY"
	keyBits           = 2048
	certRequestType   = "CERTIFICATE REQUEST"
	certPath          = "./certs/"
)

func main() {
	// gen CA key
	caKey := genKey()
	caKeySaveErr := keySaveToFile(caKey, certPath+"ca_key.pem")
	failIfErr(caKeySaveErr, "")

	// get CA Root cert
	caCert, caCertGenErr := certGenCA(caKey)
	failIfErr(caCertGenErr, "")
	caCertSaveErr := certSaveToFile(caCert, certPath+"ca_cert")
	failIfErr(caCertSaveErr, "")

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

func genKey() *rsa.PrivateKey {
	k, err := keyGen()
	failIfErr(err, "")

	return k
}
