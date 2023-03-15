package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

var (
	key       = RandBytes(256 / 8)
	gcm       cipher.AEAD
	nonceSize int
)

// Initilze GCM for both encrypting and decrypting on program start.
func init() {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("Error reading key: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Key: %s\n", hex.EncodeToString(key))

	gcm, err = cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Error initializing AEAD: %s\n", err.Error())
		os.Exit(1)
	}

	nonceSize = gcm.NonceSize()
}

func RandBytes(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}

func encrypt(plaintext []byte) (ciphertext []byte) {
	nonce := randBytes(nonceSize)
	c := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, c...)
}

func decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("Ciphertext too short.")
	}
	nonce := ciphertext[0:nonceSize]
	msg := ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, msg, nil)
}

func main() {
	fmt.Println("Encrypting...")
	msg := []byte("The quick brown fox jumped over the lazy dog.")
	ciphertext := encrypt(msg)
	fmt.Printf("Encrypted message: %v\n", ciphertext)

	fmt.Println("Decrypting...")
	plaintext, err := decrypt(ciphertext)
	if err != nil {
		// Don't display this message to the end-user, as it could potentially
		// give an attacker useful information. Just tell them something like "Failed to decrypt."
		fmt.Printf("Error decryping message: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Decrypted message: %s\n", string(plaintext))
}
