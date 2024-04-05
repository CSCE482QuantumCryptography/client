package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

func RSAKem(conn net.Conn) ([]byte, error) {
	fmt.Println("Generating key pair!")

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)

	fmt.Println("Client pub key len: ", len(publicKeyBytes))
	// publicKey := base64.StdEncoding.EncodeToString(publicKeyBytes)

	fmt.Println("Writing public key to server!")
	writePubKeyStart := time.Now()
	conn.Write(publicKeyBytes)
	writePubKeyEnd := time.Now()
	timeMap["writeClientPubKey"] = []time.Time{writePubKeyStart, writePubKeyEnd}
	fmt.Println("Reading cipher text!")

	ciphertext := make([]byte, 256)

	fmt.Println("Reading ciphertext from server")

	readCipherTextStart := time.Now()
	_, err = readFromServer(conn, ciphertext, 256)
	if err != nil {
		return nil, err
	}
	readCipherTextEnd := time.Now()
	timeMap["readCipherText"] = []time.Time{readCipherTextStart, readCipherTextEnd}

	fmt.Println("Decaping secret")

	decapSecretStart := time.Now()
	sharedSecretClient, err := DecapSecret(ciphertext, privKey)
	if err != nil {
		return nil, err
	}
	decapSecretEnd := time.Now()
	timeMap["decapSecret"] = []time.Time{decapSecretStart, decapSecretEnd}

	fmt.Println("sharedSecret: ", sharedSecretClient)
	fmt.Println("Returning")
	fmt.Println()

	return sharedSecretClient, nil

}

func DecapSecret(ciphertext []byte, clientPrivKey *rsa.PrivateKey) ([]byte, error) {

	sharedSecretClient, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, clientPrivKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return sharedSecretClient, nil

}
