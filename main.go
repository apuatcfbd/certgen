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
	caCert, caCertBytes, caCertGenErr := certGenCA(caKey)
	failIfErr(caCertGenErr, "")
	caCertSaveErr := certSaveToFile(caCertBytes, certPath+"ca_cert.pem")
	failIfErr(caCertSaveErr, "")

	// issue server cert using CA

	// gen server key
	serverKey := genKey()
	serverKeySaveErr := keySaveToFile(serverKey, certPath+"server_key.pem")
	failIfErr(serverKeySaveErr, "")

	// gen server cert
	_, serverCertBytes, serverCertGenErr := certGenServer(caCert, caKey, serverKey)
	failIfErr(serverCertGenErr, "")
	serverCertSaveErr := certSaveToFile(serverCertBytes, certPath+"server_cert.pem")
	failIfErr(serverCertSaveErr, "")

}

func genKey() *rsa.PrivateKey {
	k, err := keyGen()
	failIfErr(err, "")

	return k
}
