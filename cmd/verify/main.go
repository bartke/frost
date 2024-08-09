package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s <hex-public-key> <hex-signature> <file>\n", os.Args[0])
	}

	hexPubKey := os.Args[1]
	hexSignature := os.Args[2]
	filePath := os.Args[3]

	pubKey, err := hex.DecodeString(hexPubKey)
	if err != nil {
		log.Fatalf("Failed to decode public key: %v\n", err)
	}

	signature, err := hex.DecodeString(hexSignature)
	if err != nil {
		log.Fatalf("Failed to decode signature: %v\n", err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read file: %v\n", err)
	}

	if ed25519.Verify(pubKey, data, signature) {
		fmt.Println("Signature is valid.")
	} else {
		fmt.Println("Signature is invalid.")
	}
}
