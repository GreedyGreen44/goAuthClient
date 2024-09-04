package main

import (
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
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
	if ok := handleError([2]byte{0x00, 0x05}, err); ok != 0 { // nonfatal, failed to form createUser request
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

// request for remove user from server database
func requestRemoveUser(tcpAddr *net.TCPAddr, currentRole string, currentUserToken []byte) int {
	if currentRole != "SUPERUSER" {
		handleError([2]byte{0x00, 0x09}, errors.New("you have no rights to do that"))
		return 1
	}
	tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
	if ok := handleError([2]byte{0x00, 0x02}, err); ok != 0 {
		return ok
	}
	requestSlice, err := sendRemoveUser(currentUserToken)
	if ok := handleError([2]byte{0x00, 0x05}, err); ok != 0 {
		return ok
	}
	_, err = tcpConn.Write(requestSlice)
	if ok := handleError([2]byte{0x00, 0x03}, err); ok != 0 {
		return ok
	}

	requestResult, err := io.ReadAll(tcpConn)
	if ok := handleError([2]byte{0x00, 0x04}, err); ok != 0 {
		return ok
	}

	switch requestResult[0] {
	case 0x0F:
		mainLog.Println("User removed")
	case 0xF0:
		mainLog.Printf("Recived Failure, error code: %v\n", requestResult[1])
	default:
		mainLog.Printf("Unexpected answer from server")
		return 1
	}

	return 0
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

// request for change users password
func requestChangePwd(tcpAddr *net.TCPAddr, currentUserToken *[]byte) int {
	if *currentUserToken == nil {
		handleError([2]byte{0x00, 0x0A}, errors.New("you are not logged in"))
		return 1
	}
	tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
	if ok := handleError([2]byte{0x00, 0x02}, err); ok != 0 {
		return ok
	}
	changePwdSlice, _ := sendChangePwd(*currentUserToken)

	_, err = tcpConn.Write(changePwdSlice)
	if ok := handleError([2]byte{0x00, 0x03}, err); ok != 0 {
		return ok
	}
	changePwdResult, err := io.ReadAll(tcpConn)
	if ok := handleError([2]byte{0x00, 0x04}, err); ok != 0 {
		return ok
	}
	switch changePwdResult[0] {
	case 0xF0:
		mainLog.Printf("Recived Failure, error code: %v\n", changePwdResult[1])
		return 1
	case 0x0F:
		mainLog.Printf("Password changed")
	default:
		mainLog.Printf("Unexpected answer from server")
		return 1
	}

	return 0
}

// request for changing users role
func requestChangeRole(tcpAddr *net.TCPAddr, currentRole *string, currentUserToken *[]byte) int {
	if *currentRole != "SUPERUSER" {
		handleError([2]byte{0x00, 0x0B}, errors.New("you have no right to do  that"))
		return 1
	}
	tcpConn, err := net.DialTCP("tcp", nil, tcpAddr)
	if ok := handleError([2]byte{0x00, 0x02}, err); ok != 0 {
		return ok
	}
	changeRoleSlice, err := sendChangeRole(*currentUserToken)
	if ok := handleError([2]byte{0x00, 0x0B}, err); ok != 0 {
		return ok
	}

	_, err = tcpConn.Write(changeRoleSlice)
	if ok := handleError([2]byte{0x00, 0x03}, err); ok != 0 {
		return ok
	}
	changeRoleResult, err := io.ReadAll(tcpConn)
	if ok := handleError([2]byte{0x00, 0x04}, err); ok != 0 {
		return ok
	}
	switch changeRoleResult[0] {
	case 0xF0:
		mainLog.Printf("Recived Failure, error code: %v\n", changeRoleResult[1])
	case 0x0F:
		mainLog.Printf("Role Changed")
	default:
		mainLog.Printf("Unexpected answer from server")
		return 1
	}
	return 0
}

// request for shutting down server
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
		os.Exit(0) // Not sure if this is the right choice to close Client via os.Exit. What if more defers will be needed?
	default:
		mainLog.Printf("Unexpected answer from server")
		return 1
	}

	return 2
}
