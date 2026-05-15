package suppliers

import (
	"crypto/rand"
	"github.com/DemonAndAngel/go-kit/fjpostapi/suppliers/crypt"
	"github.com/DemonAndAngel/go-kit/json"
)

type CryptoHelper struct {
	rsaCli *crypt.Rsa
	sm4Cli *crypt.SM4
	aesIv  string
}

func (h *CryptoHelper) EncryptRequest(requestBody any) (aesBodyEn string, rsaAesKeyEn string, err error) {
	aesKey := make([]byte, 16)
	if _, err = rand.Read(aesKey); err != nil {
		return "", "", err
	}
	bodyStr := json.JsonMarshal(requestBody)
	aesBodyEn, err = crypt.AESEncrypt(string(aesKey), h.aesIv, bodyStr)
	if err != nil {
		return "", "", err
	}

	rsaAesKeyEn, err = h.rsaCli.Encrypt(string(aesKey))
	if err != nil {
		return "", "", err
	}

	return
}

func (h *CryptoHelper) DecryptRequest(aesBodyEn, rsaAesKeyEn string) (requestBody any, err error) {
	aesKey, err := h.rsaCli.Decrypt(rsaAesKeyEn)
	if err != nil {
		return nil, err
	}

	bodyStr, err := crypt.AESDecrypt(aesKey, h.aesIv, aesBodyEn)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(bodyStr), &requestBody)
	if err != nil {
		return nil, err
	}

	return requestBody, nil
}
