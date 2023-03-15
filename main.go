package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
)

// variable declarations for CLI flags
var (
	keyType   string
	keyLength int
)

func main() {
	// parse CLI flags
	flag.StringVar(&keyType, "type", "aes", "Type of key to generate. (aes, rsa)")
	flag.IntVar(&keyLength, "length", 256, "Length of key to generate. (128, 256, 512)")
	flag.Parse()

	// generate key
	var key []byte
	switch keyType {
	case "aes":
		key = aes.RandBytes(keyLength / 8)
	case "rsa":
		key = aes.RandBytes(keyLength / 8)
	default:
		log.Fatal("Invalid key type.")
	}

	// print key
	fmt.Printf("Key: %s\n", hex.EncodeToString(key))
}
