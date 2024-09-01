package main

import (
	"crypto/md5"
	"errors"
	"fmt"
)

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

// forms request to remove user
func sendRemoveUser(token []byte) ([]byte, error) {
	var inputUserName string
	for {
		fmt.Println("Enter user name...")
		_, err := fmt.Scan(&inputUserName)
		if ok := handleError([2]byte{0x00, 0x01}, err); ok != 0 {
			continue
		}
		break
	}
	var (
		requestSlice []byte
		commandByte  byte
	)

	commandByte = 0x11
	requestSlice = append(requestSlice, commandByte)
	requestSlice = append(requestSlice, token...)
	requestSlice = append(requestSlice, byte(len(inputUserName)))
	requestSlice = append(requestSlice, inputUserName...)

	return requestSlice, nil
}

// forms authentication request
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

// forms request for shutting down server
func sendShutDown(token []byte) ([]byte, error) {
	shutDownSlice := []byte{0x01}
	shutDownSlice = append(shutDownSlice, token...)
	return shutDownSlice, nil
}
