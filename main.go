package main

import (
	"fmt"
	"syscall"

	"golang.org/x/term"
)

// promptPassword prompts user to enter password for vault decryption
func promptPassword() ([]byte, error) {
	fmt.Print("Enter vault password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	fmt.Println()
	return password, nil
}

func main() {
	password, err := promptPassword()
	if err != nil {
		fmt.Errorf("Failed to read password: %v", err)
	}

	fmt.Print(password)
}
