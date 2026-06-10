// Package oldaes implements AES/ECB/PKCS5Padding encryption compatible with
// the Java AESEncryptUtils utility used by the Fujian Post platform.
package oldaes

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"errors"
)

// Encrypt encrypts plaintext with the given key using AES/ECB/PKCS5Padding,
// then returns the result as a base64-encoded string.
func Encrypt(plaintext, key string) (string, error) {
	ciphertext, err := ecbEncrypt([]byte(plaintext), []byte(key))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decodes the base64 ciphertext and decrypts it with the given key
// using AES/ECB/PKCS5Padding, returning the original plaintext.
func Decrypt(ciphertext, key string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	plaintext, err := ecbDecrypt(raw, []byte(key))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// ecbEncrypt performs AES-ECB encryption with PKCS5/PKCS7 padding.
func ecbEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	plaintext = pkcs5Pad(plaintext, bs)

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += bs {
		block.Encrypt(ciphertext[i:i+bs], plaintext[i:i+bs])
	}
	return ciphertext, nil
}

// ecbDecrypt performs AES-ECB decryption and removes PKCS5/PKCS7 padding.
func ecbDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(ciphertext) == 0 || len(ciphertext)%bs != 0 {
		return nil, errors.New("oldaes: ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += bs {
		block.Decrypt(plaintext[i:i+bs], ciphertext[i:i+bs])
	}
	return pkcs5Unpad(plaintext, bs)
}

// pkcs5Pad pads data to a multiple of blockSize using PKCS5/PKCS7.
func pkcs5Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs5Unpad removes PKCS5/PKCS7 padding.
func pkcs5Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("oldaes: empty data")
	}
	padding := int(data[length-1])
	if padding == 0 || padding > blockSize || padding > length {
		return nil, errors.New("oldaes: invalid padding size")
	}
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("oldaes: invalid padding bytes")
		}
	}
	return data[:length-padding], nil
}
