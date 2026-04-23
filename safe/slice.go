package safe

import (
	"errors"
)

// SubSlice 安全地裁剪切片末尾。n 为要裁剪的长度。
func SubSlice(data []byte, n int) ([]byte, error) {
	length := len(data)
	if n < 0 || n > length {
		return nil, errors.New("slice bounds out of range")
	}
	return data[:length-n], nil
}

// SubString 安全地裁剪字符串末尾。n 为要裁剪的长度。
func SubString(s string, n int) (string, error) {
	length := len(s)
	if n < 0 || n > length {
		return "", errors.New("string bounds out of range")
	}
	return s[:length-n], nil
}
