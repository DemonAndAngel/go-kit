package crypt

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// RSA加密
func RsaEncrypt(str string, cert string) (string, error) {
	buf := []byte(cert)
	//pem解码
	block, _ := pem.Decode(buf)
	if block == nil {
		return "", errors.New("cert is error")
	}
	//x509解码
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	//类型断言
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	//对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(str))
	if err != nil {
		return "", err
	}
	//返回密文
	return string(cipherText), nil
}

// RSA解密
// cipherText 需要解密的byte数据
// path 私钥文件路径
func RsaDecrypt(str string, cert string) (string, error) {
	buf := []byte(cert)
	//pem解码
	block, _ := pem.Decode(buf)
	if block == nil {
		return "", errors.New("cert is error")
	}
	//X509解码
	privateKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	privateKey := privateKeyInterface.(*rsa.PrivateKey)
	//对密文进行解密
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, []byte(str))
	//返回明文
	return string(plainText), nil
}

type Rsa struct {
	PrivateKey string
	PublicKey  string
	Private    *rsa.PrivateKey
	Public     *rsa.PublicKey
}

func NewRsa(privateKey, publicKey string) (*Rsa, error) {
	if privateKey == "" && publicKey == "" {
		return nil, errors.New("privateKey Or publicKey is Nil")
	}

	r := &Rsa{}

	// 初始化私钥对象
	if privateKey != "" {
		block, _ := pem.Decode([]byte(privateKey))
		pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		r.Private = pk.(*rsa.PrivateKey)
		r.PrivateKey = privateKey
	}

	// 初始化公钥对象
	if publicKey != "" {
		b, _ := pem.Decode([]byte(publicKey))
		pub, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		r.Public = pub.(*rsa.PublicKey)
		r.PublicKey = publicKey
	} else {
		r.Public = &r.Private.PublicKey
	}

	return r, nil
}

// Sign 签名
func (r *Rsa) Sign(data []byte, hash crypto.Hash) ([]byte, error) {
	if r.Private == nil {
		return nil, errors.New("生成签名失败")
	}
	h := hash.New()
	h.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, r.Private, hash, h.Sum(nil))
}

// Verify 验签
func (r *Rsa) Verify(sign, data []byte, hash crypto.Hash) error {
	if r.Public == nil {
		return errors.New("验证签名失败")
	}
	h := hash.New()
	h.Write(data)
	return rsa.VerifyPKCS1v15(r.Public, hash, h.Sum(nil), sign)
}

// Encrypt 加密
// 加密公钥/8 - 11 = 最长加密明文长度
func (r *Rsa) Encrypt(data []byte) ([]byte, error) {
	if r.Public == nil {
		return nil, errors.New("加密失败")
	}
	lengh := r.Public.N.BitLen()/8 - 11 //  最长可加密明文长度
	if lengh >= len(data) {
		return rsa.EncryptPKCS1v15(rand.Reader, r.Public, data)
	}

	buffer := bytes.NewBufferString("")
	pages := len(data) / lengh
	for i := 0; i < pages; i++ {
		start := i * lengh
		end := (i + 1) * lengh

		if start >= len(data) {
			continue
		}

		if end > len(data) {
			end = len(data)
		}

		b, err := rsa.EncryptPKCS1v15(rand.Reader, r.Public, data[start:end])
		if err != nil {
			return nil, err
		}

		buffer.Write(b)
	}
	return buffer.Bytes(), nil
}

// Decrypt 解密
func (r *Rsa) Decrypt(data []byte) ([]byte, error) {
	if r.Private == nil {
		return nil, errors.New("解密失败")
	}
	// 加密后生成固定长度（加密公钥/8）的密文，所以分段不需要减去11
	lengh := r.Public.N.BitLen() / 8 // 分段解密最大长度
	fmt.Println(len(data), lengh)
	if lengh > len(data) {
		return rsa.DecryptPKCS1v15(rand.Reader, r.Private, data)
	}

	buffer := bytes.NewBufferString("")
	pages := len(data) / lengh
	for i := 0; i < pages; i++ {
		start := i * lengh
		end := (i + 1) * lengh

		if start >= len(data) {
			continue
		}

		if end > len(data) {
			end = len(data)
		}

		b, err := rsa.DecryptPKCS1v15(rand.Reader, r.Private, data[start:end])
		if err != nil {
			return nil, err
		}

		buffer.Write(b)
	}
	return buffer.Bytes(), nil
}
