package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/CSCE482QuantumCryptography/qs509"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func readFromServer(conn net.Conn, buf []byte, readLen int) (int, error) {
	totalRead := 0
	for totalRead < readLen {
		n, err := conn.Read(buf[totalRead:])
		if err != nil {
			return 0, err
		}
		totalRead += n
	}
	return totalRead, nil

}

func main() {

	opensslPath := flag.String("openssl-path", "../../build/bin/openssl", "the path to openssl 3.3")
	opensslCNFPath := flag.String("openssl-cnf-path", "../../openssl/apps/openssl.cnf", "the path to openssl config")
	dst := flag.String("dst", "127.0.0.1:9080", "the address being dialed")
	signingAlg := flag.String("sa", "DILITHIUM3", "the algorithm used to sign the client certificate")
	kemAlg := flag.String("ka", "Kyber512", "the algorithm used for generating shared secret")

	// Parse flags
	flag.Parse()

	qs509.Init(*opensslPath, *opensslCNFPath)

	var sa qs509.SignatureAlgorithm
	sa.Set(*signingAlg)

	qs509.GenerateCsr(sa, "client_private_key.key", "client_csr.csr")
	qs509.SignCsr("./client_csr.csr", "client_signed_crt.crt", "../qs509/etc/crt/dilithium3_CA.crt", "../qs509/etc/keys/dilithium3_CA.key")

	clientCertFile, err := os.ReadFile("client_signed_crt.crt")
	if err != nil {
		panic(err)
	}

	clientCertLen := make([]byte, 4)
	binary.BigEndian.PutUint32(clientCertLen, uint32(len(clientCertFile)))

	fmt.Println("Client Certificate Size: ", len(clientCertFile))

	conn, err := net.Dial("tcp", *dst)
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
	_, err = readFromServer(conn, serverCertLenBytes, 4)
	if err != nil {
		panic(err)
	}

	serverCertLenInt := int(binary.BigEndian.Uint32(serverCertLenBytes))

	fmt.Println("Server cert size: ", serverCertLenInt)

	serverCertFile := make([]byte, serverCertLenInt)
	_, err = readFromServer(conn, serverCertFile, serverCertLenInt)
	if err != nil {
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

	kemName := *kemAlg
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

	ciphertext := make([]byte, client.Details().LengthCiphertext)

	_, err = readFromServer(conn, ciphertext, client.Details().LengthCiphertext)
	if err != nil {
		panic(err)
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

	iv := make([]byte, block.BlockSize())

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
