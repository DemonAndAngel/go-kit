package crypt

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256生成哈希值
func Sha256(str string) string {
	//创建一个基于SHA256算法的hash.Hash接口的对象
	hash := sha256.New()
	//输入数据
	hash.Write([]byte(str))
	//计算哈希值
	bytes := hash.Sum(nil)
	//将字符串编码为16进制格式,返回字符串
	hashCode := hex.EncodeToString(bytes)
	//返回哈希值
	return hashCode
}
