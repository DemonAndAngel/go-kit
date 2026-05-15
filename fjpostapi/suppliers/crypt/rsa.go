package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

type Rsa struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

func NewRsa(privateKey, publicKey string) (*Rsa, error) {
	if privateKey == "" && publicKey == "" {
		return nil, errors.New("privateKey Or publicKey is Nil")
	}

	r := &Rsa{}

	// 初始化私钥对象
	if privateKey != "" {
		rsaPk, err := x509.ParsePKCS1PrivateKey([]byte(privateKey))
		if err != nil {
			return nil, err
		}
		r.Private = rsaPk
	}

	// 初始化公钥对象
	if publicKey != "" {
		pub, err := x509.ParsePKIXPublicKey([]byte(publicKey))
		if err != nil {
			return nil, err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("parsed public key is not RSA")
		}
		r.Public = rsaPub
	} else {
		r.Public = &r.Private.PublicKey
	}

	return r, nil
}

// OAEP 加密
func (r *Rsa) Encrypt(data string) (dataEnBase64 string, err error) {
	if r.Public == nil {
		return "", errors.New("加密失败")
	}

	dataEnByte, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.Public, []byte(data), nil)
	if err != nil {
		return "", err
	}

	dataEnBase64 = base64.StdEncoding.EncodeToString(dataEnByte)

	return dataEnBase64, nil
}

// Decrypt 解密
func (r *Rsa) Decrypt(dataEnBase64 string) (data string, err error) {
	if r.Private == nil {
		return "", errors.New("解密失败")
	}
	dataEnByte, err := base64.StdEncoding.DecodeString(dataEnBase64)
	if err != nil {
		return "", err
	}
	oaep, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		r.Private,
		dataEnByte,
		nil, // PSource.PSpecified.DEFAULT
	)
	if err != nil {
		return "", err
	}

	data = string(oaep)

	return data, nil
}
