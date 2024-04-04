package main

import (
	"fmt"
	"net"
	"time"

	"github.com/CSCE482QuantumCryptography/qs509"
)

func main() {

	totalTimeStart := time.Now()

	// Create and sign CSR for client
	clientCertFile, clientCertLen, err := CreateCsr()
	if err != nil {
		panic(err)
	}

	// Dial server
	conn, err := net.Dial("tcp", *dst)
	if err != nil {
		panic(err)
	}

	defer func() {
		fmt.Println("Closing connection with the server!")
		qs509.BenchmarkMap(timeMap, *signingAlg, *kemAlg, "../"+*signingAlg+"_"+*kemAlg+".xlsx", "client")
		conn.Close()

		for key, value := range timeMap {
			executionTime := value[1].Sub(value[0])
			fmt.Print(key + ": ")
			fmt.Println(executionTime)
		}

	}()

	certAuthStart := time.Now()
	// Cert Auth
	_, err = CertAuth(conn, clientCertLen, clientCertFile)
	if err != nil {
		panic(err)
	}
	certAuthEnd := time.Now()
	timeMap["certAuth"] = []time.Time{certAuthStart, certAuthEnd}

	// KEM

	kemStart := time.Now()
	sharedSecretClient, err := OqsKem(conn)
	if err != nil {
		panic(err)
	}
	kemEnd := time.Now()
	timeMap["kem"] = []time.Time{kemStart, kemEnd}

	// AES

	aesStart := time.Now()
	stream, reader, err := SetupAES(conn, sharedSecretClient)
	if err != nil {
		panic(err)
	}
	aesEnd := time.Now()
	timeMap["aes"] = []time.Time{aesStart, aesEnd}

	totalTimeEnd := time.Now()
	timeMap["TotalTime"] = []time.Time{totalTimeStart, totalTimeEnd}

	// Constantly send messages to Server
	for {
		fmt.Print("Text to send (q to exit): ")

		input, _ := reader.ReadString('\n')

		input = input[:len(input)-1]

		if input == "q" {
			break
		}

		dataToWrite := []byte(input)

		encrypted := make([]byte, len(dataToWrite))

		encryptMessageStart := time.Now()
		stream.XORKeyStream(encrypted, dataToWrite)
		encryptMessageEnd := time.Now()
		timeMap["encryptMessage"] = []time.Time{encryptMessageStart, encryptMessageEnd}

		writeEncryptedMsgStart := time.Now()
		writeLen, writeErr := conn.Write(encrypted)
		writeEncryptedMsgEnd := time.Now()
		timeMap["writeEncryptedMsg"] = []time.Time{writeEncryptedMsgStart, writeEncryptedMsgEnd}

		if writeErr != nil {
			fmt.Errorf("Write Error:", writeErr)
			return
		}

		fmt.Println("Encrypted Data Written:", encrypted, writeLen)

	}

}
