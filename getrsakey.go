package goEncrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

/*
	Asymmetric encryption requires the generation of a pair of keys rather than a key, so before encryption here you need to get a pair of keys, public and private, respectively
	Generate the public and private keys all at once
		Encryption: plaintext to the power E Mod N to output ciphertext
		Decryption: ciphertext to the power D Mod N outputs plaintext

		Encryption operations take a long time? Encryption is faster

		The data is encrypted and cannot be easily decrypted
*/

func GetRsaKey() (privateBuffer bytes.Buffer,publicBuffer bytes.Buffer,err error) {
	// private
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, err
	}
	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	privateBlock := pem.Block{
		Type:  privateKeyPrefix,
		Bytes: x509PrivateKey,
	}

	if err = pem.Encode(&privateBuffer, &privateBlock); err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, err
	}

	// public
	publicKey := privateKey.PublicKey
	x509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, err
	}
	publicBlock := pem.Block{
		Type:  publicKeyPrefix,
		Bytes: x509PublicKey,
	}
	if err = pem.Encode(&publicBuffer, &publicBlock); err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, err
	}

	return privateBuffer, publicBuffer, nil
}
