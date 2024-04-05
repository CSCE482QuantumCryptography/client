package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/CSCE482QuantumCryptography/qs509"
)

func CreateCsr() ([]byte, []byte, error) {
	var sa qs509.SignatureAlgorithm
	sa.Set(*signingAlg)

	signCsrStart := time.Now()
	qs509.GenerateCsr(sa, "client_private_key.key", "client_csr.csr")
	qs509.SignCsr("./client_csr.csr", "client_signed_crt.crt", *caCert, *caKey)
	signCsrEnd := time.Now()

	timeMap["signCsr"] = []time.Time{signCsrStart, signCsrEnd}

	clientCertFile, err := os.ReadFile("client_signed_crt.crt")
	if err != nil {
		return nil, nil, err
	}

	clientCertLen := make([]byte, 4)
	binary.BigEndian.PutUint32(clientCertLen, uint32(len(clientCertFile)))

	fmt.Println("Client Certificate Size: ", len(clientCertFile))

	return clientCertFile, clientCertLen, nil
}
