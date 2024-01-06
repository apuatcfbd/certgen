package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func keyGenerate() (key *rsa.PrivateKey, err error) {
	priKey, keyErr := rsa.GenerateKey(rand.Reader, keyBits)
	if keyErr != nil {
		return nil, keyErr
	}

	return priKey, nil
}

func keySaveToFile(k *rsa.PrivateKey, path string) error {
	keyPem := &pem.Block{
		Type:  pemPrivateKeyType,
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	}

	certPrivKeyPEM := pem.EncodeToMemory(keyPem)
	writeToFile(path, certPrivKeyPEM, 0600)
	return nil
}

func keyGetFromFile(path string) (key *rsa.PrivateKey, err error) {
	keyBytes := readFromFile(path)
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != pemPrivateKeyType {
		return nil, errors.New("failed to decode PEM block containing private key from " + path)
	}

	key, keyParseErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if keyParseErr != nil {
		return nil, errors.New("failed to parse private key from " + path)
	}

	return key, nil
}

func keyGetSum(k *rsa.PrivateKey) string {
	keyPem := &pem.Block{
		Type:  pemPrivateKeyType,
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	}

	h := sha256.New()
	pemB := pem.EncodeToMemory(keyPem)
	h.Write(pemB)

	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}
