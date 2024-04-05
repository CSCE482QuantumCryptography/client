package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"time"
)

func ECKem(conn net.Conn) ([]byte, error) {

	fmt.Println("Generating EC key pair!")

	genECKeyPairStart := time.Now()
	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	clientPubKey := clientPrivKey.PublicKey
	genECKeyPairEnd := time.Now()
	timeMap["genECKeyPair"] = []time.Time{genECKeyPairStart, genECKeyPairEnd}

	clientPubECDHKey, err := clientPubKey.ECDH()
	if err != nil {
		return nil, err
	}

	fmt.Println("Client pub ecdh key len: ", len(clientPubECDHKey.Bytes()))

	fmt.Println("Sending client pub key to server!")
	writeClientKeyStart := time.Now()
	conn.Write(clientPubECDHKey.Bytes())
	writeClientKeyEnd := time.Now()
	timeMap["writeClientKey"] = []time.Time{writeClientKeyStart, writeClientKeyEnd}

	fmt.Println("Reading server ecdh key")

	serverPubECDHKeyBytes := make([]byte, 65)

	readServerKeyStart := time.Now()
	_, err = readFromServer(conn, serverPubECDHKeyBytes, 65)
	if err != nil {
		return nil, err
	}
	readServerKeyEnd := time.Now()
	timeMap["readServerKey"] = []time.Time{readServerKeyStart, readServerKeyEnd}

	serverPubECDHKey, err := ecdh.P256().NewPublicKey(serverPubECDHKeyBytes)
	if err != nil {
		return nil, err
	}

	fmt.Println("Getting shared secret!")

	clientPrivECDHKey, err := clientPrivKey.ECDH()
	if err != nil {
		return nil, err
	}

	genSecretStart := time.Now()
	clientSharedSecret, err := clientPrivECDHKey.ECDH(serverPubECDHKey)
	if err != nil {
		return nil, err
	}
	genSecretEnd := time.Now()
	timeMap["genSecret"] = []time.Time{genSecretStart, genSecretEnd}

	return clientSharedSecret, nil

}
