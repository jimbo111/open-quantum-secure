package main

import (
	"crypto/aes"
	"crypto/cipher"
)

const KeySize = 256

func main() {
	key := make([]byte, KeySize/8)
	block, _ := aes.NewCipher(key)
	_, _ = cipher.NewGCM(block)
}
