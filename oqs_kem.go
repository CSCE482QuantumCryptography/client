package main

import (
	"fmt"
	"net"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func OqsKem(conn net.Conn) ([]byte, error) {
	kemName := *kemAlg
	client := oqs.KeyEncapsulation{}
	defer client.Clean() // clean up even in case of panic

	if err := client.Init(kemName, nil); err != nil {
		return nil, err
	}

	generateKEMKeyPairStart := time.Now()
	clientPublicKey, err := client.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	generateKEMKeyPairEnd := time.Now()
	timeMap["generateKemKeyPair"] = []time.Time{generateKEMKeyPairStart, generateKEMKeyPairEnd}

	fmt.Println("\nKEM details:")
	fmt.Println(client.Details())
	fmt.Println()

	fmt.Println("Sending public kyber key to server!")
	writeClientPubKeyStart := time.Now()
	conn.Write(clientPublicKey)
	writeClientPubKeyEnd := time.Now()
	timeMap["writeClientPubKey"] = []time.Time{writeClientPubKeyStart, writeClientPubKeyEnd}

	ciphertext := make([]byte, client.Details().LengthCiphertext)

	readCipherTextStart := time.Now()
	_, err = readFromServer(conn, ciphertext, client.Details().LengthCiphertext)
	if err != nil {
		return nil, err
	}
	readCipherTextEnd := time.Now()
	timeMap["readCipherText"] = []time.Time{readCipherTextStart, readCipherTextEnd}

	fmt.Println("Received shared secret from server!")

	decapSecretStart := time.Now()
	sharedSecretClient, err := client.DecapSecret(ciphertext)
	if err != nil {
		return nil, err
	}
	decapSecretEnd := time.Now()
	timeMap["decapSecret"] = []time.Time{decapSecretStart, decapSecretEnd}

	return sharedSecretClient, nil
}
