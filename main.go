package main

const (
	pemCertType       = "CERTIFICATE"
	pemPrivateKeyType = "RSA PRIVATE KEY"
	pemPublicKeyType  = "RSA PUBLIC KEY"
	keyBits           = 2048
	certPath          = "./certs/"
)

func main() {
	keyMain()
}
