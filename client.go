package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"

	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {

	startTime := time.Now()

	conn, err := net.Dial("tcp", "127.0.0.1:9080")

	if err != nil {
		panic(err)
	}

	defer func() {
		fmt.Println("Closing connection with the server!")
		conn.Close()
	}()

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

	conn.Write(clientPublicKey)

	ciphertext := make([]byte, 768)

	_, ciphertextReadErr := conn.Read(ciphertext)
	if ciphertextReadErr != nil {
		panic("Error reading ciphertext!")
	}

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

	endTime := time.Now()
	executionTime := endTime.Sub(startTime)

	fmt.Println("Execution time: ", executionTime)

	// BENCHMARK
}
