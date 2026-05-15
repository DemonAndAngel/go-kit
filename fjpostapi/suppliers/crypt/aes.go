package crypt

import (
	"crypto/aes"
	"encoding/base64"
	"errors"

	"github.com/CrimsonAIO/aesccm"
)

const (
	ccmNonceSize = 10
	ccmTagSize   = 8
)

func AESEncrypt(key, iv, data string) (string, error) {
	if len(iv) != ccmNonceSize {
		return "", errors.New("invalid CCM nonce length")
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	ccm, err := aesccm.NewCCM(block, ccmNonceSize, ccmTagSize)
	if err != nil {
		return "", err
	}

	ciphertext := ccm.Seal(nil, []byte(iv), []byte(data), nil)

	encryptDataBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return encryptDataBase64, nil
}

func AESDecrypt(key, iv, encryptDataBase64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptDataBase64)
	if err != nil {
		return "", err
	}

	if len(iv) != ccmNonceSize {
		return "", errors.New("invalid CCM nonce length")
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	ccm, err := aesccm.NewCCM(block, ccmNonceSize, ccmTagSize)
	if err != nil {
		return "", err
	}

	plaintext, err := ccm.Open(nil, []byte(iv), ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
