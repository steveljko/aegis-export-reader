package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"syscall"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

type VaultData struct {
	Version int    `json:"version"`
	Header  Header `json:"header"`
	DB      string `json:"db"`
}

type Header struct {
	Slots  []Slot `json:"slots"`
	Params Params `json:"params"`
}

type Slot struct {
	Type      int    `json:"type"`
	UUID      string `json:"uuid"`
	Key       string `json:"key"`
	KeyParams Params `json:"key_params"`
	N         int    `json:"n"`
	R         int    `json:"r"`
	P         int    `json:"p"`
	Salt      string `json:"salt"`
}

type Params struct {
	Nonce string `json:"nonce"`
	Tag   string `json:"tag"`
}

type AegisVault struct {
	Entries []Entry
}

type Entry struct {
	Type   string `json:"type"`
	UUID   string `json:"uuid"`
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
	Icon   string `json:"icon,omitempty"`
	Info   Info   `json:"info"`
}

type Info struct {
	Secret    string `json:"secret"`
	Algorithm string `json:"algo"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period,omitempty"`
	Counter   int64  `json:"counter,omitempty"`
}

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

// decryptVault decrypts vault by providing vault path and decryption password
func decryptVault(vaultPath string, password []byte) ([]Entry, error) {
	data, err := ioutil.ReadFile(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault file: %v", err)
	}

	var vaultData VaultData
	if err = json.Unmarshal(data, &vaultData); err != nil {
		return nil, fmt.Errorf("failed to parse vault JSON: %v", err)
	}

	var passwordSlots []Slot
	for _, slot := range vaultData.Header.Slots {
		if slot.Type == 1 { // password slot type
			passwordSlots = append(passwordSlots, slot)
		}
	}

	var masterKey []byte
	for _, slot := range passwordSlots {
		salt, err := hex.DecodeString(slot.Salt)
		if err != nil {
			continue
		}

		derivedKey, err := scrypt.Key(password, salt, slot.N, slot.R, slot.P, 32)
		if err != nil {
			continue
		}

		nonce, err := hex.DecodeString(slot.KeyParams.Nonce)
		if err != nil {
			continue
		}

		keyData, err := hex.DecodeString(slot.Key)
		if err != nil {
			continue
		}

		tag, err := hex.DecodeString(slot.KeyParams.Tag)
		if err != nil {
			continue
		}

		ciphertext := append(keyData, tag...)

		block, err := aes.NewCipher(derivedKey)
		if err != nil {
			continue
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}

		masterKey, err = gcm.Open(nil, nonce, ciphertext, nil)
		if err == nil {
			break // successfully decrypted
		}
	}

	if masterKey == nil {
		return nil, fmt.Errorf("unable to decrypt master key with given password")
	}

	content, err := base64.StdEncoding.DecodeString(vaultData.DB)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault content: %v", err)
	}

	nonce, err := hex.DecodeString(vaultData.Header.Params.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %v", err)
	}

	tag, err := hex.DecodeString(vaultData.Header.Params.Tag)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tag: %v", err)
	}

	ciphertext := append(content, tag...)

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	dbBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vault: %v", err)
	}

	var vault AegisVault
	if err := json.Unmarshal(dbBytes, &vault); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted vault: %v", err)
	}

	return vault.Entries, nil
}

// NewVault creates new vault instance and decrypts it
func NewVault(vaultPath string, password []byte) (*AegisVault, error) {
	entries, err := decryptVault(vaultPath, password)
	if err != nil {
		return nil, err
	}

	return &AegisVault{Entries: entries}, nil
}

func main() {
	password, err := promptPassword()
	if err != nil {
		fmt.Printf("Failed to read password: %v\n", err)
		return
	}

	var vaultPath string
	flag.StringVar(&vaultPath, "vault", "", "Path to the vault file")
	flag.StringVar(&vaultPath, "v", "", "Path to the vault file (shorthand)")

	flag.Parse()

	vault, err := NewVault(vaultPath, password)
	if err != nil {
		fmt.Printf("Failed to create vault: %v\n", err)
		return
	}

	// print vault entries
	for _, entry := range vault.Entries {
		fmt.Printf("Entry UUID: %s, Name: %s, Issuer: %s\n", entry.UUID, entry.Name, entry.Issuer)
	}
}
