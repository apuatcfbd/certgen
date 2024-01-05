package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

func privateKeyToEncryptedPEM(bits int, pwd string) []byte {
	// Generate the key of length bits
	key, err := rsa.GenerateKey(rand.Reader, bits)
	failIfErr(err, "PrivateKey Generation Failed")

	keyPub := &key.PublicKey

	// Convert it to pem
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	// Encrypt the pem
	if pwd != "" {

		encryptedBytes, encErr := rsa.EncryptPKCS1v15(
			rand.Reader,
			keyPub,
			[]byte(pwd),
		)
		failIfErr(encErr, "Key encryption failed")

		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(pwd), x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
	}

	return pem.EncodeToMemory(block), nil
}

func encryptKey(key *rsa.PublicKey, pwd string) []byte {
	encryptedBytes, encErr := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		key,
		[]byte(pwd),
		nil,
	)
	failIfErr(encErr, "Key encryption failed")

	return encryptedBytes
}

func decryptKey(priKey *rsa.PrivateKey, encrypted []byte) []byte {
	decryptedBytes, err := priKey.Decrypt(
		nil,
		encrypted,
		&rsa.OAEPOptions{Hash: crypto.SHA256},
	)
	failIfErr(err, "Key decryption failed")
	return decryptedBytes
}
