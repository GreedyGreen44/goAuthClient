package main

func handleError(errorCode [2]byte, err error) int {
	if err == nil {
		return 0
	}
	switch errorCode[0] {
	case 0x00: // nonfatal
		switch errorCode[1] {
		case 0x00:
			errorLog.Printf("Failed to process command: %v\n", err)
		case 0x01:
			errorLog.Printf("Failed to scan input command, try again: %v\n", err)
		case 0x02:
			errorLog.Printf("Failed to establish connection to server: %v\n", err)
		case 0x03:
			errorLog.Printf("Failed to send command to server: %v\n", err)
		case 0x04:
			errorLog.Printf("Failed to read answer from server: %v\n", err)
		case 0x05:
			errorLog.Printf("Failed to form creqteUser request: %v\n", err)
		case 0x06:
			errorLog.Printf("Failed to form login request: %v\n", err)
		case 0x07:
			errorLog.Printf("Failed to form logout request: %v\n", err)
		case 0x08:
			errorLog.Printf("Failed to form shutdown request: %v\n", err)
		case 0x09:
			errorLog.Printf("Failed to form removeUser request: %v\n", err)
		case 0x0A:
			errorLog.Printf("Failed to form password change request: %v\n", err)
		default:
			errorLog.Printf("Unexpected minor error code %v, proceed with care\n", int(errorCode[1]))
		}
		return 1
	case 0x01: // fatal
		switch errorCode[1] {
		case 0x01:
			errorLog.Printf("Failed to form tcp address: %v, shutting down Program\n", err)
		default:
			errorLog.Printf("Unexpected minor error code %v, shutting down Program\n", int(errorCode[1]))
		}
		return 2
	default:
		errorLog.Printf("Unexpected sernior error code %v, shutting down Program\n", int(errorCode[0]))
		return 2
	}
}
