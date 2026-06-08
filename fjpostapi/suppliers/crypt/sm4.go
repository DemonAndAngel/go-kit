package crypt

import (
	"encoding/hex"
	"github.com/tjfoc/gmsm/sm4"
)

type SM4 struct {
	key string
}

func NewSM4(key string) *SM4 {
	return &SM4{
		key: key,
	}
}
func (s *SM4) Encrypt(plainText string) (string, error) {
	en, err := sm4.Sm4Ecb([]byte(s.key), []byte(plainText), true)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(en), nil
}

func (s *SM4) Decrypt(cipherText string) (string, error) {
	enB, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	de, err := sm4.Sm4Ecb([]byte(s.key), enB, false)
	if err != nil {
		return "", err
	}
	return string(de), nil
}
