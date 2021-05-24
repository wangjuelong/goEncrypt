package goEncrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
)

func init() {
	log.SetFlags(log.Ldate | log.Lshortfile)
}

// GetEccKey get ecc key
func GetEccKey() (privateBuffer bytes.Buffer, publicBuffer bytes.Buffer, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, err
	}

	x509PrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, err
	}

	block := pem.Block{
		Type:  eccPrivateKeyPrefix,
		Bytes: x509PrivateKey,
	}
	if err = pem.Encode(&privateBuffer, &block); err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, err
	}
	x509PublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, err
	}
	publicBlock := pem.Block{
		Type:  eccPublicKeyPrefix,
		Bytes: x509PublicKey,
	}
	if err = pem.Encode(&publicBuffer, &publicBlock); err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, err
	}

	return privateBuffer, publicBuffer, nil
}
