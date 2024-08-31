package main

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
)

// request to test server connection
func requestTest(tcpAddr *net.TCPAddr) int {
	tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
	if ok := handleError([2]byte{0x00, 0x02}, err); ok != 0 { // nonfatal, failed to establish connection to server
		return ok
	}
	var helloSlice []byte
	helloSlice = append(helloSlice, 0xAA)

	_, err = tcpConn.Write(helloSlice)
	if ok := handleError([2]byte{0x00, 0x03}, err); ok != 0 { // nonfatal, failed to send command to server
		return ok
	}

	connectionResult, err := io.ReadAll(tcpConn)
	if ok := handleError([2]byte{0x00, 0x04}, err); ok != 0 { // nonfatal, failed to read answer from server
		return ok
	}

	switch connectionResult[0] {
	case 0x0F: // Proceed
		mainLog.Println("Connection test successful")
	case 0xF0: // Disconnect
		mainLog.Printf("Recived Failure, error code: %v\n", connectionResult[1])
	default:
		mainLog.Printf("Unexpected answer from server")
		return 1
	}
	return 0
}

// request for creating new user in server database
func requestRegistration(tcpAddr *net.TCPAddr, currentRole string, currentUserToken []byte) int {
	if currentRole != "SUPERUSER" {
		handleError([2]byte{0x00, 0x05}, errors.New("you have no rights to do that")) // nonfatal, failed to form shutdown request
		return 1
	}
	tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
	if ok := handleError([2]byte{0x00, 0x02}, err); ok != 0 { // nonfatal, failed to establish connection to server
		return ok
	}
	createSlice, err := sendCreateUser(currentUserToken)
	if ok := handleError([2]byte{0x00, 0x05}, err); ok != 0 { // momfatal, failed to form createUser request
		return ok
	}
	_, err = tcpConn.Write(createSlice)
	if ok := handleError([2]byte{0x00, 0x03}, err); ok != 0 { // nonfatal, failed to send command to server
		return ok
	}

	connectionResult, err := io.ReadAll(tcpConn)
	if ok := handleError([2]byte{0x00, 0x04}, err); ok != 0 { // nonfatal, failed to read answer from server
		return ok
	}
	switch connectionResult[0] {
	case 0x0F: // Proceed
		mainLog.Println("New user created")
	case 0xF0: // Disconnect
		mainLog.Printf("Recived Failure, error code: %v\n", connectionResult[1])
	default:
		mainLog.Printf("Unexpected answer from server")
		return 1
	}
	return 0
}

// scans new users login, password and desired role and result in request
func sendCreateUser(token []byte) ([]byte, error) {
	var inputUserName, inputPassword1, inputPassword2, inputRole string
	for {
		fmt.Println("Enter user new username...")
		_, err := fmt.Scan(&inputUserName)
		if ok := handleError([2]byte{0x00, 0x01}, err); ok != 0 {
			continue
		}
		break
	}
	for {
		fmt.Println("Enter password...")
		_, err := fmt.Scan(&inputPassword1)
		if ok := handleError([2]byte{0x00, 0x01}, err); ok != 0 {
			continue
		}
		fmt.Println("Enter password again...")
		_, err = fmt.Scan(&inputPassword2)
		if ok := handleError([2]byte{0x00, 0x01}, err); ok != 0 {
			continue
		}
		if inputPassword1 != inputPassword2 {
			fmt.Println("Passwords do not match")
			continue
		}
		break
	}
	for {
		fmt.Println("Enter role...")
		_, err := fmt.Scan(&inputRole)
		if ok := handleError([2]byte{0x00, 0x01}, err); ok != 0 {
			continue
		}
		break
	}

	requestSlice, err := formNewUser(inputUserName, inputPassword1, inputRole, token)
	if err != nil {
		return nil, err
	}

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

// request for login into system
func requestLogin(tcpAddr *net.TCPAddr, currentUserState *string, currentRole *string, currentUserToken *[]byte) int {
	if *currentUserState != "Guest" {
		handleError([2]byte{0x00, 0x06}, errors.New("you are already logged in")) //nonfatal, failed to form login request
		return 1
	}
	tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
	if ok := handleError([2]byte{0x00, 0x02}, err); ok != 0 { // nonfatal, failed to establish connection to server
		return ok
	}
	loginSlice, loginString, err := sendLogin()
	if ok := handleError([2]byte{0x00, 0x06}, err); ok != 0 {
		return ok
	}

	_, err = tcpConn.Write(loginSlice)
	if ok := handleError([2]byte{0x00, 0x03}, err); ok != 0 { // nonfatal, failed to send command to server
		return ok
	}

	connectionResult, err := io.ReadAll(tcpConn)
	if ok := handleError([2]byte{0x00, 0x04}, err); ok != 0 { // nonfatal, failed to read answer from server
		return ok
	}

	switch connectionResult[0] {
	case 0x0F: // Proceed
		token := connectionResult[3:]
		switch connectionResult[2] {
		case 0x01:
			mainLog.Printf("Welcome, %s, your token is %s\n", loginString, hex.EncodeToString(token))
			*currentRole = "SUPERUSER"
		case 0x02:
			mainLog.Printf("Welcome, %s, your token is %s\n", loginString, hex.EncodeToString(token))
			*currentRole = "ADMIN"
		case 0x03:
			mainLog.Printf("Welcome, %s, your token is %s\n", loginString, hex.EncodeToString(token))
			*currentRole = "USER"
		}
		*currentUserState = loginString
		*currentUserToken = token
	case 0xF0: // Disconnect
		mainLog.Printf("Recived Failure, error code: %v\n", connectionResult[1])
	default:
		mainLog.Printf("Unexpected answer from server")
		return 1
	}
	return 0
}

// forms authentification request
func sendLogin() ([]byte, string, error) {
	var inputUserName, inputPassword string
	for {
		fmt.Println("Enter username...")
		_, err := fmt.Scan(&inputUserName)
		if ok := handleError([2]byte{0x00, 0x01}, err); ok != 0 {
			continue
		}
		break
	}
	for {
		fmt.Println("Enter password...")
		_, err := fmt.Scan(&inputPassword)
		if ok := handleError([2]byte{0x00, 0x01}, err); ok != 0 {
			continue
		}
		break
	}

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

// request for logout of system
func requestLogout(tcpAddr *net.TCPAddr, currentUserState *string, currentUserToken *[]byte, currentRole *string) int {
	if *currentUserState == "Guest" {
		handleError([2]byte{0x00, 0x07}, errors.New("you are not logged in")) // nonfatal, failed to from logout request
		return 1
	}
	tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
	if ok := handleError([2]byte{0x00, 0x02}, err); ok != 0 { // nonfatal, failed to establish connection to server
		return ok
	}
	logoutSlice, _ := sendLogout(*currentUserToken)

	_, err = tcpConn.Write(logoutSlice)
	if ok := handleError([2]byte{0x00, 0x03}, err); ok != 0 { // nonfatal, failed to send command to server
		return ok
	}

	logoutResult, err := io.ReadAll(tcpConn)
	if ok := handleError([2]byte{0x00, 0x04}, err); ok != 0 { // nonfatal, failed to read answer from server
		return ok
	}
	switch logoutResult[0] {
	case 0x0F:
		mainLog.Printf("Logged out")
		*currentUserState = "Guest"
		currentUserToken = nil
		*currentRole = "UNASSIGNED"
	case 0xF0:
		mainLog.Printf("Recived Failure, error code: %v\n", logoutResult[1])
	default:
		mainLog.Printf("Unexpected answer from server")
		return 1
	}
	return 0
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

// reqeust for shutting down server
func requestShutdown(tcpAddr *net.TCPAddr, currentRole *string, currentUserToken *[]byte) int {
	if *currentRole != "SUPERUSER" {
		handleError([2]byte{0x00, 0x08}, errors.New("you have no rights to do that")) // nonfatal, failed to form shutdown request
		return 1
	}
	tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
	if ok := handleError([2]byte{0x00, 0x02}, err); ok != 0 { // nonfatal, failed to establish connection to server
		return ok
	}
	shutDownSlice, _ := sendShutDown(*currentUserToken)

	_, err = tcpConn.Write(shutDownSlice)
	if ok := handleError([2]byte{0x00, 0x03}, err); ok != 0 { // nonfatal, failed to send command to server
		return ok
	}
	shutdownResult, err := io.ReadAll(tcpConn)
	if ok := handleError([2]byte{0x00, 0x04}, err); ok != 0 { // nonfatal, failed to read answer from server
		return ok
	}
	switch shutdownResult[0] {
	case 0xF0:
		mainLog.Printf("Recived Failure, error code: %v\n", shutdownResult[1])
		return 1
	case 0x0F:
		mainLog.Printf("Server shut down")
	default:
		mainLog.Printf("Unexpected answer from server")
		return 1
	}

	return 2
}

// forms request for shutting down serever
func sendShutDown(token []byte) ([]byte, error) {
	shutDownSlice := []byte{0x01}
	shutDownSlice = append(shutDownSlice, token...)
	return shutDownSlice, nil
}
