package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
