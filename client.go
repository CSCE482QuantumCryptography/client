package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/CSCE482QuantumCryptography/qs509"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
	qs509.Init("../../build/bin/openssl", "../../openssl/apps/openssl.cnf")

	var d3_sa qs509.SignatureAlgorithm
	d3_sa.Set("DILITHIUM3")

	qs509.GenerateCsr(d3_sa, "client_private_key.key", "client_csr.csr")
	qs509.SignCsr("./client_csr.csr", "client_signed_crt.crt", "../qs509/etc/crt/dilithium3_CA.crt", "../qs509/etc/keys/dilithium3_CA.key")

	clientCertFile, err := os.ReadFile("client_signed_crt.crt")
	if err != nil {
		panic(err)
	}

	clientCertLen := make([]byte, 4)
	binary.BigEndian.PutUint32(clientCertLen, uint32(len(clientCertFile)))

	fmt.Println("Client Certificate Size: ", len(clientCertFile))

	conn, err := net.Dial("tcp", "127.0.0.1:9080")
	if err != nil {
		panic(err)
	}

	defer func() {
		fmt.Println("Closing connection with the server!")
		conn.Close()
	}()

	// Cert Auth
	fmt.Println("Reading Server Certificate!")
	serverCertLenBytes := make([]byte, 4)
	_, err = conn.Read(serverCertLenBytes)
	if err != nil {
		panic(err)
	}
	serverCertLenInt := int(binary.BigEndian.Uint32(serverCertLenBytes))

	fmt.Println("Server cert size: ", serverCertLenInt)

	serverCertFile := make([]byte, serverCertLenInt)
	_, err = conn.Read(serverCertFile)
	if err != nil && err != io.EOF {
		panic(err)
	}

	isValid, err := qs509.VerifyCertificate("../qs509/etc/crt/dilithium3_CA.crt", serverCertFile)
	if err != nil {
		panic(err)
	}

	if !isValid {
		panic("I dont trust this server!")
	}

	fmt.Println("Verified Server Certificate!")

	fmt.Println("Writing my certificate to server!")
	_, err = conn.Write(clientCertLen)
	if err != nil {
		panic(err)
	}

	_, err = conn.Write(clientCertFile)
	if err != nil {
		panic(err)
	}

	fmt.Println()

	// KEM

	kemName := "Kyber512"
	client := oqs.KeyEncapsulation{}
	defer client.Clean() // clean up even in case of panic

	if err := client.Init(kemName, nil); err != nil {
		panic(err)
	}

	clientPublicKey, err := client.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	fmt.Println("\nKEM details:")
	fmt.Println(client.Details())
	fmt.Println()

	fmt.Println("Sending public kyber key to server!")
	conn.Write(clientPublicKey)

	ciphertext := make([]byte, 768)

	_, ciphertextReadErr := conn.Read(ciphertext)
	if ciphertextReadErr != nil {
		panic("Error reading ciphertext!")
	}

	fmt.Println("Received shared secret from server!")

	sharedSecretClient, err := client.DecapSecret(ciphertext)
	if err != nil {
		panic(err)
	}

	// AES

	block, cipherErr := aes.NewCipher(sharedSecretClient)

	if cipherErr != nil {
		fmt.Errorf("Create cipher error:", cipherErr)

		return
	}

	iv := make([]byte, aes.BlockSize)

	if _, randReadErr := io.ReadFull(rand.Reader, iv); randReadErr != nil {
		fmt.Errorf("Can't build random iv", randReadErr)

		return
	}

	_, ivWriteErr := conn.Write(iv)

	if ivWriteErr != nil {
		fmt.Errorf("IV send Error:", ivWriteErr)

		return
	} else {
		fmt.Println("IV Sent:", iv)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Text to send (q to exit): ")

		input, _ := reader.ReadString('\n')

		input = input[:len(input)-1]

		if input == "q" {
			break
		}

		dataToWrite := []byte(input)

		encrypted := make([]byte, len(dataToWrite))

		stream.XORKeyStream(encrypted, dataToWrite)

		writeLen, writeErr := conn.Write(encrypted)

		if writeErr != nil {
			fmt.Errorf("Write Error:", writeErr)
			return
		}

		fmt.Println("Encrypted Data Written:", encrypted, writeLen)

	}

}
