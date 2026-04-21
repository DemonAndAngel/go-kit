package crypt

import (
	"crypto/aes"
	"errors"
	"fmt"
)

// AesECBDecrypt AES-ECB解密（PKCS7填充，移除所有panic）
func AesECBDecrypt(aesKey []byte, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return []byte{}, fmt.Errorf("创建AES块失败：%w", err)
	}
	blockSize := block.BlockSize()

	// 提前检查密文长度（替代panic）
	if len(cipherText)%blockSize != 0 {
		return nil, fmt.Errorf("密文长度(%d)不是AES块大小(%d)的整数倍", len(cipherText), blockSize)
	}

	// 初始化解密缓冲区
	decrypted := make([]byte, len(cipherText))
	// 逐块解密（无panic，提前校验）
	for i := 0; i < len(cipherText); i += blockSize {
		end := i + blockSize
		// 二次校验（防止数组越界，替代panic）
		if end > len(cipherText) {
			return nil, errors.New("密文长度异常，解密时数组越界")
		}
		block.Decrypt(decrypted[i:end], cipherText[i:end])
	}

	// 去除PKCS7填充
	decrypted, err = pkcs7Unpad(decrypted, blockSize)
	if err != nil {
		return nil, fmt.Errorf("PKCS7去填充失败：%w", err)
	}

	return decrypted, nil
}

// pkcs7Unpad 去除PKCS7填充（返回错误而非nil）
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("待去填充数据为空")
	}
	// 最后一个字节是填充长度
	padLen := int(data[len(data)-1])
	// 验证填充长度合法性
	if padLen > blockSize || padLen == 0 {
		return nil, fmt.Errorf("无效的填充长度：%d（块大小：%d）", padLen, blockSize)
	}
	// 验证填充内容
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, errors.New("填充内容不匹配，可能是密钥错误或数据损坏")
		}
	}
	// 去除填充
	return data[:len(data)-padLen], nil
}
