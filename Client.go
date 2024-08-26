package main

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

var mainLog *log.Logger

func main() {
	mainLog = log.New(os.Stdout, "client:", log.LstdFlags)
	/*if len(os.Args) != 2 {
		mainLog.Printf("Usage: %s mode ", os.Args[0])
		os.Exit(1)
	}

	mode := os.Args[1]*/
	service := "localhost:3241"
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	handleError(err)
	currentUserState := "Guest"
	currentUserToken := make([]byte, 0)
	currentRole := "UNASSIGNED"
	for {
		var inputCommand string
		fmt.Printf("%s:", currentUserState)
		_, err := fmt.Scanln(&inputCommand)
		if err != nil {
			handleError(err)
		}
		switch inputCommand {
		case "test":
			tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
			handleError(err)

			var helloSlice []byte
			helloSlice = append(helloSlice, 0xAA)

			_, err = tcpConn.Write(helloSlice)
			handleError(err)
			connectionResult, err := io.ReadAll(tcpConn)
			handleError(err)
			switch connectionResult[0] {
			case 0x0F: // Proceed
				mainLog.Println("Connection test successful")
			case 0xF0: // Disconnect
				mainLog.Printf("Recived Failure, error code: %v\n", connectionResult[1])
			default:
				mainLog.Printf("Unexpected answer from server")
				os.Exit(1)
			}
		case "registration":
			if currentRole != "SUPERUSER" {
				mainLog.Println("You have no rights to do that!")
				continue
			}
			tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
			handleError(err)
			createSlice, err := sendCreateUser(currentUserToken)
			handleError(err)
			_, err = tcpConn.Write(createSlice)
			handleError(err)

			connectionResult, err := io.ReadAll(tcpConn)
			handleError(err)
			switch connectionResult[0] {
			case 0x0F: // Proceed
				mainLog.Println("New user created")
			case 0xF0: // Disconnect
				mainLog.Printf("Recived Failure, error code: %v\n", connectionResult[1])
			default:
				mainLog.Printf("Unexpected answer from server")
				os.Exit(1)
			}
		case "login":
			if currentUserState != "Guest" {
				mainLog.Println("You already logged in")
				continue
			}
			tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
			handleError(err)
			loginSlice, loginString, err := sendLogin()
			handleError(err)

			_, err = tcpConn.Write(loginSlice)
			handleError(err)

			connectionResult, err := io.ReadAll(tcpConn)
			handleError(err)

			switch connectionResult[0] {
			case 0x0F: // Proceed
				token := connectionResult[3:]
				switch connectionResult[2] {
				case 0x01:
					mainLog.Printf("Welcome, %s, your token is %s\n", loginString, hex.EncodeToString(token))
					currentRole = "SUPERUSER"
				case 0x02:
					mainLog.Printf("Welcome, %s, your token is %s\n", loginString, hex.EncodeToString(token))
					currentRole = "ADMIN"
				case 0x03:
					mainLog.Printf("Welcome, %s, your token is %s\n", loginString, hex.EncodeToString(token))
					currentRole = "USER"
				}
				currentUserState = loginString
				currentUserToken = token
			case 0xF0: // Disconnect
				mainLog.Printf("Recived Failure, error code: %v\n", connectionResult[1])
			default:
				mainLog.Printf("Unexpected answer from server")
				os.Exit(1)
			}
		case "logout":
			if currentUserState == "Guest" {
				mainLog.Println("You are not logged in")
				continue
			}
			tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
			handleError(err)
			logoutSlice, err := sendLogout(currentUserToken)
			handleError(err)

			_, err = tcpConn.Write(logoutSlice)
			handleError(err)

			logoutResult, err := io.ReadAll(tcpConn)
			handleError(err)
			switch logoutResult[0] {
			case 0x0F:
				mainLog.Printf("Logged out")
				currentUserState = "Guest"
				currentUserToken = nil
				currentRole = "UNASSIGNED"
			case 0xF0:
				mainLog.Printf("Recived Failure, error code: %v\n", logoutResult[1])
			default:
				mainLog.Printf("Unexpected answer from server")
				os.Exit(1)
			}
		case "shutdown":
			if currentRole != "SUPERUSER" {
				mainLog.Println("You have no rights to do that!")
				continue
			}
			tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
			handleError(err)
			shutDownSlice, err := sendShutDown(currentUserToken)
			handleError(err)

			_, err = tcpConn.Write(shutDownSlice)
			handleError(err)
			return
		case "exit":
			return
		default:
			mainLog.Println("Unknown command")
		}
	}
}

// lazy handling errors
func handleError(err error) {
	if err != nil {
		mainLog.Printf("Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

// scans new users login, password and desired role and result in request
func sendCreateUser(token []byte) ([]byte, error) {
	var inputUserName, inputPassword1, inputPassword2, inputRole string
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

	requestSlice, err := formNewUser(inputUserName, inputPassword1, inputRole, token)
	handleError(err)

	return requestSlice, nil
}

// forms request for creating new user
func formNewUser(name, password, role string, token []byte) ([]byte, error) {
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
	requestSlice = append(requestSlice, token...)
	requestSlice = append(requestSlice, roleByte)
	requestSlice = append(requestSlice, byte(len(name)))
	requestSlice = append(requestSlice, name...)
	requestSlice = append(requestSlice, byte(hashSize))
	requestSlice = append(requestSlice, hashValue...)

	return requestSlice, nil
}

// calculates md5 hash for password
func calculateMD5(input string) (hashValue []byte, hashSize int) {
	hash := md5.New()
	hash.Write([]byte(input))
	hashValue = hash.Sum(nil)
	hashSize = hash.Size()
	return
}

// forms authentification request
func sendLogin() ([]byte, string, error) {
	var inputUserName, inputPassword string
	fmt.Println("Enter username...")
	_, err := fmt.Scan(&inputUserName)
	handleError(err)
	fmt.Println("Enter password...")
	_, err = fmt.Scan(&inputPassword)
	handleError(err)

	if len(inputUserName) > 255 {
		return nil, "", errors.New("username is too long")
	}

	hashValue, hashSize := calculateMD5(inputPassword)

	var (
		requestSlice []byte
		commandByte  byte
	)

	commandByte = 0x20
	requestSlice = append(requestSlice, commandByte)
	requestSlice = append(requestSlice, byte(len(inputUserName)))
	requestSlice = append(requestSlice, inputUserName...)
	requestSlice = append(requestSlice, byte(hashSize))
	requestSlice = append(requestSlice, hashValue...)

	return requestSlice, inputUserName, nil
}

// forms request fro logout
func sendLogout(token []byte) ([]byte, error) {
	var (
		requestSlice []byte
		commandByte  byte
	)

	commandByte = 0x21
	requestSlice = append(requestSlice, commandByte)
	requestSlice = append(requestSlice, token...)
	return requestSlice, nil

}

// forms request for shutting down serever
func sendShutDown(token []byte) ([]byte, error) {
	shutDownSlice := []byte{0x01}
	shutDownSlice = append(shutDownSlice, token...)
	return shutDownSlice, nil
}
