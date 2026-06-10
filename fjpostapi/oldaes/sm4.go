package oldaes

import (
	"encoding/base64"
	"strings"

	"github.com/tjfoc/gmsm/sm4"
)

const (
	// SM4 ciphertext prefix used by the Java CryptoThirdSM4Tools.
	sm4Prefix = "|$4|"
	// Legacy AES-128 ciphertext prefix.
	aesPrefix = "|$|"
)

// SM4Encrypt encrypts plaintext using SM4/ECB/PKCS5Padding.
// The key is a base64-encoded string (decoded to 16 raw bytes before use).
// Returns the ciphertext as a base64-encoded string with the "|$4|" prefix.
// If plaintext is empty or already prefixed, it is returned as-is.
func SM4Encrypt(plaintext, base64Key string) (string, error) {
	if plaintext == "" || base64Key == "" {
		return plaintext, nil
	}
	if strings.HasPrefix(plaintext, sm4Prefix) || strings.HasPrefix(plaintext, aesPrefix) {
		return plaintext, nil
	}

	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", err
	}

	ciphertext, err := sm4.Sm4Ecb(key, []byte(plaintext), true)
	if err != nil {
		return "", err
	}

	return sm4Prefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// SM4Decrypt decrypts ciphertext produced by SM4Encrypt (or the Java counterpart).
// The key is a base64-encoded string. The function handles:
//   - "|$4|" prefix: SM4/ECB decryption
//   - "|$|" prefix: legacy AES/ECB decryption (key also base64-decoded)
//   - no prefix: returns ciphertext as-is
func SM4Decrypt(ciphertext, base64Key string) (string, error) {
	if ciphertext == "" || base64Key == "" {
		return ciphertext, nil
	}

	if strings.HasPrefix(ciphertext, sm4Prefix) {
		raw := strings.TrimPrefix(ciphertext, sm4Prefix)
		return sm4DecryptBase64(raw, base64Key)
	}

	if strings.HasPrefix(ciphertext, aesPrefix) {
		raw := strings.TrimPrefix(ciphertext, aesPrefix)
		return aesDecryptBase64(raw, base64Key)
	}

	return ciphertext, nil
}

// sm4DecryptBase64 decodes the base64 ciphertext and decrypts with SM4/ECB.
func sm4DecryptBase64(data, base64Key string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", err
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	plaintext, err := sm4.Sm4Ecb(key, cipherBytes, false)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// aesDecryptBase64 handles the legacy "|$|" prefix: AES/ECB with base64-decoded key.
func aesDecryptBase64(data, base64Key string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", err
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	plaintext, err := ecbDecrypt(cipherBytes, key)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
