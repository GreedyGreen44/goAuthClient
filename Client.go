package main

import (
	"crypto/md5"
	"errors"
	"io"
	"log"
	"net"
	"os"
)

var mainLog *log.Logger

func main() {
	mainLog = log.New(os.Stdout, "client:", log.LstdFlags)
	if len(os.Args) != 2 {
		mainLog.Printf("Usage: %s mode ", os.Args[0])
		os.Exit(1)
	}

	mode := os.Args[1]
	service := "localhost:3241"
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	handleError(err)
	switch mode {
	case "test":
		tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
		handleError(err)

		var helloSlice []byte
		helloSlice = append(helloSlice, 0xAA)

		_, err = tcpConn.Write(helloSlice)
		handleError(err)
		connectionResult, err := io.ReadAll(tcpConn)
		handleError(err)
		if len(connectionResult) != 2 {
			mainLog.Printf("Unexpected answer from server")
			os.Exit(1)
		}
		switch connectionResult[0] {
		case 0x0F: // Proceed
			mainLog.Println("Recived Proceed")
		case 0xF0: // Disconnect
			mainLog.Println("Recived Disconnect")
		default:
			mainLog.Printf("Unexpected answer from server")
			os.Exit(1)
		}
	case "registartion":
		tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
		handleError(err)
		createSlice, err := sendCreateUser()
		handleError(err)
		_, err = tcpConn.Write(createSlice)
		handleError(err)
	}

	mainLog.Printf("Connection established to %v\n", tcpAddr)
	os.Exit(0)
}

func handleError(err error) {
	if err != nil {
		mainLog.Printf("Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

func sendCreateUser() ([]byte, error) {
	/*var inputUserName, inputPassword1, inputPassword2, inputRole string
	fmt.Println("Enter user new username...")
	_, err := fmt.Scan(&inputUserName)
	handleError(err)
	for {
		fmt.Println("Enter password...")
		_, err = fmt.Scan(&inputPassword1)
		handleError(err)
		fmt.Println("Enter password again...")
		_, err = fmt.Scan(&inputPassword2)
		handleError(err)
		if inputPassword1 != inputPassword2 {
			fmt.Println("Passwords do not match")
			continue
		}
		break
	}
	fmt.Println("Enter role...")
	_, err = fmt.Scan(&inputRole)
	handleError(err)
	*/
	inputUserName := "Superuser"
	inputPassword1 := "superuser"
	inputRole := "SUPERUSER"

	requestSlice, err := formNewUser(inputUserName, inputPassword1, inputRole)
	handleError(err)

	return requestSlice, nil
}

func formNewUser(name, password, role string) ([]byte, error) {
	if len(name) > 255 {
		return nil, errors.New("username is too long")
	}
	hashValue, hashSize := calculateMD5(password)
	var commandByte, roleByte byte
	commandByte = 0x10
	switch role {
	case "USER":
		roleByte = 0x13
	case "ADMIN":
		roleByte = 0x12
	case "SUPERUSER":
		roleByte = 0x11
	default:
		return nil, errors.New("unknown Role")
	}

	var requestSlice []byte
	requestSlice = append(requestSlice, commandByte)
	requestSlice = append(requestSlice, roleByte)
	requestSlice = append(requestSlice, byte(len(name)))
	requestSlice = append(requestSlice, name...)
	requestSlice = append(requestSlice, byte(hashSize))
	requestSlice = append(requestSlice, hashValue...)

	return requestSlice, nil
}

func calculateMD5(input string) (hashValue []byte, hashSize int) {
	hash := md5.New()
	hash.Write([]byte(input))
	hashValue = hash.Sum(nil)
	hashSize = hash.Size()
	return
}
