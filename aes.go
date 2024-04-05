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
)

func SetupAES(conn net.Conn, sharedSecretClient []byte) (cipher.Stream, *bufio.Reader, error) {
	block, cipherErr := aes.NewCipher(sharedSecretClient)

	if cipherErr != nil {
		fmt.Errorf("Create cipher error:", cipherErr)

		return nil, nil, cipherErr
	}

	iv := make([]byte, block.BlockSize())

	if _, randReadErr := io.ReadFull(rand.Reader, iv); randReadErr != nil {
		fmt.Errorf("Can't build random iv", randReadErr)

		return nil, nil, randReadErr
	}

	_, ivWriteErr := conn.Write(iv)

	if ivWriteErr != nil {
		fmt.Errorf("IV send Error:", ivWriteErr)

		return nil, nil, ivWriteErr
	} else {
		fmt.Println("IV Sent:", iv)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	reader := bufio.NewReader(os.Stdin)

	return stream, reader, nil
}
