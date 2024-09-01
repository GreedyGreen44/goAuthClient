package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
)

var mainLog *log.Logger
var errorLog *log.Logger

func main() {
	mainLog = log.New(os.Stdout, "client:", log.LstdFlags)
	errorLog = log.New(os.Stdout, "error:", log.LstdFlags)
	service := "localhost:3241"
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	if ok := handleError([2]byte{0x01, 0x01}, err); ok != 0 { // fatal, failed to form server tcp adress
		return
	}

	currentUserState := "Guest"
	currentUserToken := make([]byte, 0)
	currentRole := "UNASSIGNED"

	defer autoLogout(tcpAddr, &currentUserState, &currentUserToken, &currentRole)
	for {
		var inputCommand string
		fmt.Printf("%s:", currentUserState)
		_, err := fmt.Scanln(&inputCommand)
		if ok := handleError([2]byte{0x00, 0x01}, err); ok != 0 { // nonfatal, failed to scan input command
			continue
		}
		var resultCode int
		switch inputCommand {
		case "test":
			resultCode = requestTest(tcpAddr)
		case "registration":
			resultCode = requestRegistration(tcpAddr, currentRole, currentUserToken)
		case "removeUser":
			resultCode = requestRemoveUser(tcpAddr, currentRole, currentUserToken)
		case "login":
			resultCode = requestLogin(tcpAddr, &currentUserState, &currentRole, &currentUserToken)
		case "logout":
			resultCode = requestLogout(tcpAddr, &currentUserState, &currentUserToken, &currentRole)
		case "shutdown":
			resultCode = requestShutdown(tcpAddr, &currentRole, &currentUserToken)
		case "exit":
			return
		default:
			resultCode = handleError([2]byte{0x00, 0x00}, errors.New("unknown command")) // nonfatal, failed to process command
		}
		if resultCode == 2 {
			return
		}
		continue
	}
}

func autoLogout(tcpAddr *net.TCPAddr, currentUserState *string, currentUserToken *[]byte, currentRole *string) {
	if *currentUserState != "Guest" {
		requestLogout(tcpAddr, currentUserState, currentUserToken, currentRole)
	}
}
