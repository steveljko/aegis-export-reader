package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
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

// saveVaultPath saves latest successful decrypted vault path
func saveVaultPath(vaultPath string) error {
	cacheFile := filepath.Join(os.TempDir(), ".vault_path")
	return os.WriteFile(cacheFile, []byte(vaultPath), 0600)
}

// loadLastVaultPath loads full path to latest successfully decrypted vault
func loadLastVaultPath() (string, error) {
	cacheFile := filepath.Join(os.TempDir(), ".vault_path")
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
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

	saveVaultPath(vaultPath)

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

// generaeteCode generates 6 digit TOTP code for specific entry by providing secret
func generateCode(secret string) (string, error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: %v", err)
	}

	timeStep := time.Now().Unix() / 30

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timeStep))

	mac := hmac.New(sha1.New, key)
	mac.Write(timeBytes)
	hash := mac.Sum(nil)

	offset := hash[19] & 0x0f
	truncatedHash := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	code := truncatedHash % 1000000

	return fmt.Sprintf("%06d", code), nil
}

// calculateTimeLeft computes remaining time until specified expiration date
func calculateTimeLeft() (int64, tcell.Color) {
	now := time.Now()
	timeLeft := 30 - (now.Unix() % 30)

	var timeColor tcell.Color
	if timeLeft <= 10 {
		timeColor = tcell.ColorRed
	} else if timeLeft <= 20 {
		timeColor = tcell.ColorYellow
	} else {
		timeColor = tcell.ColorGreen
	}

	return timeLeft, timeColor
}

func renderInterface(vault *AegisVault) error {
	app := tview.NewApplication()

	table := tview.NewTable().
		SetBorders(true).
		SetSelectable(true, false).
		SetFixed(1, 0)

	table.SetCell(0, 0, tview.NewTableCell("Issuer").SetTextColor(tcell.ColorYellow).SetAlign(tview.AlignCenter))
	table.SetCell(0, 1, tview.NewTableCell("Name").SetTextColor(tcell.ColorYellow).SetAlign(tview.AlignCenter))
	table.SetCell(0, 2, tview.NewTableCell("Code").SetTextColor(tcell.ColorYellow).SetAlign(tview.AlignCenter))
	table.SetCell(0, 3, tview.NewTableCell("Time Left").SetTextColor(tcell.ColorYellow).SetAlign(tview.AlignCenter))

	var entries = vault.GetAll()
	for i, entry := range entries {
		row := i + 1

		table.SetCell(row, 0, tview.NewTableCell(entry.Issuer).SetTextColor(tcell.ColorWhite))
		table.SetCell(row, 1, tview.NewTableCell(entry.Name).SetTextColor(tcell.ColorWhite))

		code, err := generateCode(entry.Info.Secret)
		if err != nil {
			table.SetCell(row, 2, tview.NewTableCell("Error").SetTextColor(tcell.ColorRed).SetAlign(tview.AlignCenter))
		} else {
			table.SetCell(row, 2, tview.NewTableCell(code).SetTextColor(tcell.ColorGreen).SetAlign(tview.AlignCenter))
		}

		left, color := calculateTimeLeft()
		table.SetCell(row, 3, tview.NewTableCell(fmt.Sprintf("%ds", left)).SetTextColor(color).SetAlign(tview.AlignCenter))
	}

	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().
			SetText("Aegist Export Reader").
			SetTextAlign(tview.AlignCenter).
			SetTextColor(tcell.ColorWhite), 1, 0, false).
		AddItem(table, 0, 1, true)

	if len(entries) > 0 {
		table.Select(1, 0)
	}

	// updates expiration time left
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			app.QueueUpdateDraw(func() {
				for i := range entries {
					row := i + 1

					left, color := calculateTimeLeft()
					table.SetCell(row, 3, tview.NewTableCell(fmt.Sprintf("%ds", left)).SetTextColor(color).SetAlign(tview.AlignCenter))

					if left == 30 {
						entry := entries[i]
						code, err := generateCode(entry.Info.Secret)
						if err != nil {
							table.SetCell(row, 2, tview.NewTableCell("Error").SetTextColor(tcell.ColorRed).SetAlign(tview.AlignCenter))
						} else {
							table.SetCell(row, 2, tview.NewTableCell(code).SetTextColor(tcell.ColorGreen).SetAlign(tview.AlignCenter))
						}
					}
				}
			})
		}
	}()

	return app.SetRoot(flex, true).EnableMouse(true).Run()
}

// NewVault creates new vault instance and decrypts it
func NewVault(vaultPath string, password []byte) (*AegisVault, error) {
	entries, err := decryptVault(vaultPath, password)
	if err != nil {
		return nil, err
	}

	return &AegisVault{Entries: entries}, nil
}

// GetAll gets all entries from vault
func (av *AegisVault) GetAll() []Entry {
	return av.Entries
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

	if vaultPath == "" {
		latestPath, _ := loadLastVaultPath()
		vaultPath = latestPath
	}

	vault, err := NewVault(vaultPath, password)
	if err != nil {
		fmt.Printf("Failed to decrypt vault: %v\n", err)
		return
	}

	if err := renderInterface(vault); err != nil {
		fmt.Println("Error loading interface")
	}
}
