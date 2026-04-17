package sign

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"io"
)

func HS1(str string, key string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(str))
	return hex.EncodeToString(mac.Sum(nil))
}

func S1(str string) string {
	h := sha1.New()
	_, _ = io.WriteString(h, str)
	return hex.EncodeToString(h.Sum(nil))
}
