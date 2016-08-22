package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// IsDirExist checks if a dir exists
func IsDirExist(path string) bool {
	fi, err := os.Stat(path)

	if err != nil {
		return os.IsExist(err)
	}

	return fi.IsDir()
}

// IsFileExist checks if a file exists
func IsFileExist(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil || os.IsExist(err)
}

// SHA512 creates sha512 string for an input data
func SHA512(body []byte) (string, error) {
	sha512h := sha512.New()
	_, err := io.Copy(sha512h, bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", sha512h.Sum(nil)), nil
}

// GenerateRSAKeyPair generate a private key and a public key
func GenerateRSAKeyPair(bits int) ([]byte, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)

	if err != nil {
		return nil, nil, err
	}

	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	pubBlock := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes}

	return pem.EncodeToMemory(privBlock), pem.EncodeToMemory(pubBlock), nil
}

// RSAEncrypt encrypts a content by a public key
func RSAEncrypt(keyBytes []byte, contentBytes []byte) ([]byte, error) {
	pubKey, err := getPubKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return rsa.EncryptPKCS1v15(rand.Reader, pubKey, contentBytes)
}

// RSADecrypt decrypts content by a private key
func RSADecrypt(keyBytes []byte, contentBytes []byte) ([]byte, error) {
	privKey, err := getPrivKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, privKey, contentBytes)
}

// SHA256Sign signs a content by a private key
func SHA256Sign(keyBytes []byte, contentBytes []byte) ([]byte, error) {
	privKey, err := getPrivKey(keyBytes)
	if err != nil {
		return nil, err
	}

	hashed := sha256.Sum256(contentBytes)
	return rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
}

// SHA256Verify verifies if a content is valid by a signed data an a public key
func SHA256Verify(keyBytes []byte, contentBytes []byte, signBytes []byte) error {
	pubKey, err := getPubKey(keyBytes)
	if err != nil {
		return err
	}

	signStr := hex.EncodeToString(signBytes)
	newSignBytes, _ := hex.DecodeString(signStr)
	hashed := sha256.Sum256(contentBytes)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], newSignBytes)
}

func getPrivKey(privBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privBytes)
	if block == nil {
		return nil, errors.New("Fail to decode private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func getPubKey(pubBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubBytes)
	if block == nil {
		return nil, errors.New("Fail to decode public key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Fail get public key from public interface")
	}

	return pubKey, nil
}
