package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

//source encode : https://gist.github.com/yingray/57fdc3264b1927ef0f984b533d63ababg
//source decode : https://gist.github.com/awadhwana/9c95377beba61293390c5fd23a3bb1df

func main() {
	// fmt.Println(string([]byte{byte(12), byte()}))
	// panic(1)

	// fmt.Println(string([]byte{119, 145, 179, 198, 215, 144, 183, 53, 162, 193, 148, 10, 221, 135, 82, 160, 253, 119, 41, 165, 18, 205, 169, 108, 104, 109, 99, 32, 11, 60, 74, 2, 242, 154, 197, 92, 121, 193, 226, 125, 224, 95, 24, 38, 133, 245,
	// 	36, 183, 34, 113, 180, 107, 198, 37, 82, 175, 113, 6, 222, 236, 210, 242, 7, 85}))
	// panic(1)

	// key := "YWRzaGpha2hkc2prYWRoamFza2hkc2pha2Roc2Foamg="
	// iv := "AAAAAAAAAAAAAAAAAAAAAA=="
	// plaintext := "abcdefghijklmnopqrstuvwxyzABCDEF"
	key := "12345678901234567890123456789012"
	iv := "1234567890123456"
	// plaintext := "Lorem ipsum dolor sit amet, consectetur adipiscing elit"
	// fmt.Printf("Result: %v\n", Ase256(plaintext, key, iv, aes.BlockSize))

	// key := []byte{119, 145, 179, 198, 215, 144, 183, 53, 162, 193, 148, 10, 221, 135, 82, 160, 253, 119, 41, 165, 18, 205, 169, 108, 104, 109, 99, 32, 11, 60, 74, 2, 242, 154, 197, 92, 121, 193, 226, 125, 224, 95, 24, 38, 133, 245, 36, 183, 34, 113, 180, 107, 198, 37, 82, 175, 113, 6, 222, 236, 210, 242, 7, 85}

	// iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	// cipherText := "b91d3ece42c203729b38ae004e96efb90109ee25f7861b6bb33891be88d9a7996a5f10bb949360bddd1f7623c15552c4"
	// cipherText := "d5GzxteQtzWiwZQK3YdSoP13KaUSzalsaG1jIAs8SgLymsVcecHifeBfGCaF9SS3InG0a8YlUq9xBt7s0vIHVQ=="
	cipherText := "bc24b69dd978d17bc3bf47b6a447951b1c713de53215ffa34559c20cbdb6554020b9d71639e850a6fed902afc1ed8bb03962591444357ac9d44c458d8f299f57"
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
