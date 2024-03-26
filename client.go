package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	// "path/filepath"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"github.com/xuri/excelize/v2"
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

	// BENCHMARK

	saveFolderPath, err := os.Getwd()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// parentDir := filepath.Dir(saveFolderPath)
	// saveParentFolderPath := parentDir

	file, err := excelize.OpenFile(saveFolderPath + "/benchmarkLog/benchmarkTime.xlsx")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() {
		// Close the spreadsheet.
		if err := file.Close(); err != nil {
			fmt.Println(err)
		}
	}()
	rows, err := file.GetRows("Sheet1")
	if err != nil {
		fmt.Println(err)
		return
	}

	// new data to add
	dataExcel := [][]interface{}{
		{startTime, "test1", executionTime},
		{startTime, "test2", executionTime},
	}
	for i, row := range rows {
		dataRow := i + 1
		for j, col := range row {
			file.SetCellValue("Sheet1", fmt.Sprintf("%s%d", string(rune(65+j)), dataRow), col)
		}
	}

	for i, row := range dataExcel {
		dataRow := i + len(rows) + 1
		for j, col := range row {
			file.SetCellValue("Sheet1", fmt.Sprintf("%s%d", string(rune(65+j)), dataRow), col)
		}
	}

	if err := file.Save(); err != nil {
		log.Fatal(err)
	}

	// NEW FILE CREATION

	// benchmark logs one instance
	fileNew := excelize.NewFile()

	headers := []string{"Access Time", "Algorithm", "Runtime"}
	for i, header := range headers {
		fileNew.SetCellValue("Sheet1", fmt.Sprintf("%s%d", string(rune(65+i)), 1), header)
	}

	for i, row := range dataExcel {
		dataRow := i + 2
		for j, col := range row {
			fileNew.SetCellValue("Sheet1", fmt.Sprintf("%s%d", string(rune(65+j)), dataRow), col)
		}
	}

	if err := fileNew.SaveAs(saveFolderPath + "/benchmarkInstance.xlsx"); err != nil {
		log.Fatal(err)
	}
}
