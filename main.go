package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

//source encode : https://gist.github.com/yingray/57fdc3264b1927ef0f984b533d63abab
//source decode : https://gist.github.com/awadhwana/9c95377beba61293390c5fd23a3bb1df

func main() {
	key := "12345678901234567890123456789012"
	iv := "1234567890123456"
	plaintext := "abcdefghijklmnopqrstuvwxyzABCDEF"
	fmt.Printf("Result: %v\n", Ase256(plaintext, key, iv, aes.BlockSize))

	cipherText := "b91d3ece42c203729b38ae004e96efb90109ee25f7861b6bb33891be88d9a7996a5f10bb949360bddd1f7623c15552c4"
	fmt.Printf("Decode : %v\n", Ase256Decode(cipherText, key, iv))
}

func Ase256(plaintext string, key string, iv string, blockSize int) string {
	bKey := []byte(key)
	bIV := []byte(iv)
	bPlaintext := PKCS5Padding([]byte(plaintext), blockSize, len(plaintext))
	block, _ := aes.NewCipher(bKey)
	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, bIV)
	mode.CryptBlocks(ciphertext, bPlaintext)
	return hex.EncodeToString(ciphertext)
}

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
func Ase256Decode(cipherText string, encKey string, iv string) (decryptedString string) {
	bKey := []byte(encKey)
	bIV := []byte(iv)
	cipherTextDecoded, err := hex.DecodeString(cipherText)
	if err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, bIV)
	mode.CryptBlocks([]byte(cipherTextDecoded), []byte(cipherTextDecoded))
	return string(PKCS5UnPadding(cipherTextDecoded))
}
