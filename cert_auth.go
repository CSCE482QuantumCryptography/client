package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/CSCE482QuantumCryptography/qs509"
)

func CertAuth(conn net.Conn, clientCertLen []byte, clientCertFile []byte) (bool, error) {
	fmt.Println("Reading Server Certificate!")
	serverCertLenBytes := make([]byte, 4)

	readServerCertStart := time.Now()
	_, err := readFromServer(conn, serverCertLenBytes, 4)
	if err != nil {
		return false, err
	}

	serverCertLenInt := int(binary.BigEndian.Uint32(serverCertLenBytes))

	fmt.Println("Server cert size: ", serverCertLenInt)

	serverCertFile := make([]byte, serverCertLenInt)
	_, err = readFromServer(conn, serverCertFile, serverCertLenInt)
	if err != nil {
		return false, err
	}
	readServerCertEnd := time.Now()
	timeMap["readServerCert"] = []time.Time{readServerCertStart, readServerCertEnd}

	verifyServerCertStart := time.Now()
	isValid, err := qs509.VerifyCertificate(*caCert, serverCertFile)
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, fmt.Errorf("I dont trust this server!")
	}
	verifyServerCertEnd := time.Now()
	timeMap["verifyServerCert"] = []time.Time{verifyServerCertStart, verifyServerCertEnd}

	fmt.Println("Verified Server Certificate!")

	fmt.Println("Writing my certificate to server!")
	writeClientCertStart := time.Now()
	_, err = conn.Write(clientCertLen)
	if err != nil {
		return false, err
	}

	_, err = conn.Write(clientCertFile)
	if err != nil {
		return false, err
	}
	writeClientCertEnd := time.Now()
	timeMap["writeClientCert"] = []time.Time{writeClientCertStart, writeClientCertEnd}

	fmt.Println()

	return true, nil
}
