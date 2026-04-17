package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

const aesKeySize = 32

/*CBC加密 按照golang标准库的例子代码
不过里面没有填充的部分,所以补上
*/

//  const (
// 	 IV = `1234567890abcdef`
//  )

// 对明文进行填充 PKCS7Padding
func padding(plainText []byte, blockSize int) []byte {
	//计算要填充的长度
	n := blockSize - len(plainText)%blockSize
	//对原来的明文填充n个n
	temp := bytes.Repeat([]byte{byte(n)}, n)
	plainText = append(plainText, temp...)
	return plainText
}

// 对密文删除填充 PKCS7UnPadding
func unPadding(cipherText []byte) []byte {
	//取出密文最后一个字节end
	end := cipherText[len(cipherText)-1]
	//删除填充
	cipherText = cipherText[:len(cipherText)-int(end)]
	return cipherText
}

// AEC加密（CBC模式）
func aesCbcEncrypt(plainText []byte, key []byte, iv string) []byte {
	aesKey := fixedAESKey(key)
	//指定加密算法，返回一个AES算法的Block接口对象
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	//进行填充
	plainText = padding(plainText, block.BlockSize())
	//指定初始向量vi,长度和block的块尺寸一致
	ivByte := []byte(iv)
	//指定分组模式，返回一个BlockMode接口对象
	blockMode := cipher.NewCBCEncrypter(block, ivByte)
	//加密连续数据库
	cipherText := make([]byte, len(plainText))
	blockMode.CryptBlocks(cipherText, plainText)
	//返回密文
	return cipherText
}

// AEC解密（CBC模式）
func aesCbcDecrypt(cipherText []byte, key []byte, iv string) []byte {
	aesKey := fixedAESKey(key)
	//指定解密算法，返回一个AES算法的Block接口对象
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	//指定初始化向量IV,和加密的一致
	ivByte := []byte(iv)
	//指定分组模式，返回一个BlockMode接口对象
	blockMode := cipher.NewCBCDecrypter(block, ivByte)
	//解密
	plainText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(plainText, cipherText)
	//删除填充
	plainText = unPadding(plainText)
	return plainText
}

func Encrypt(rawData string, key string, iv string) (raw string, err error) {
	defer func() {
		if errStr := recover(); errStr != nil {
			err = errors.New("数据加密失败,请检查密钥.")
		}
		return
	}()
	data := aesCbcEncrypt([]byte(rawData), []byte(key), iv)
	raw = base64.StdEncoding.EncodeToString(data)
	return
}

func Decrypt(rawData string, key string, iv string) (raw string, err error) {
	defer func() {
		if errStr := recover(); errStr != nil {
			err = errors.New("请求异常")
		}
		return
	}()
	data, err := base64.StdEncoding.DecodeString(rawData)
	if err != nil {
		return
	}
	dByte := aesCbcDecrypt(data, []byte(key), iv)
	raw = string(dByte)
	return
}

func fixedAESKey(key []byte) []byte {
	aesKey := make([]byte, aesKeySize)
	copy(aesKey, key)
	return aesKey
}

func EncryptWithHex(rawData string, key string, iv string) (raw string, err error) {
	defer func() {
		if errStr := recover(); errStr != nil {
			err = errors.New("数据加密失败,请检查密钥.")
		}
		return
	}()
	data := aesCbcEncrypt([]byte(rawData), []byte(key), iv)
	raw = hex.EncodeToString(data)
	return
}

func DecryptWithHex(rawData string, key string, iv string) (raw string, err error) {
	defer func() {
		if errStr := recover(); errStr != nil {
			err = errors.New("请求异常")
		}
		return
	}()
	data, err := hex.DecodeString(rawData)
	if err != nil {
		return
	}
	dByte := aesCbcDecrypt(data, []byte(key), iv)
	raw = string(dByte)
	return
}

// AESECBEncrypt 加密 【模拟了Java SHA1PRNG处理】
func AESECBEncrypt(data []byte, encryptKey string) ([]byte, error) {
	key, err := AesSha1prng([]byte(encryptKey), 128)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(generateKey(key))
	if err != nil {
		return nil, err
	}

	data = PKCS5Padding(data, block.BlockSize())
	decrypted := make([]byte, len(data))
	size := block.BlockSize()
	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Encrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted, nil
}

// 模拟java SHA1PRNG 处理
func AesSha1prng(keyBytes []byte, encryptLength int) ([]byte, error) {
	hashs := Sha1(Sha1(keyBytes))
	maxLen := len(hashs)
	realLen := encryptLength / 8
	if realLen > maxLen {
		return nil, errors.New("invalid length")
	}

	return hashs[0:realLen], nil
}

func Sha1(data []byte) []byte {
	sum := sha1.Sum(data)
	return sum[:]
}

func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}

	return genKey
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	n := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(n)}, n)
	return append(ciphertext, padtext...)
}
