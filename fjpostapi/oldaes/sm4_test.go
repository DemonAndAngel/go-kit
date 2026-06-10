package oldaes

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSM4EncryptDecrypt(t *testing.T) {
	// 16-byte SM4 key, base64-encoded
	rawKey := []byte("1234567890abcdef")
	b64Key := base64.StdEncoding.EncodeToString(rawKey)

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple", "hello world"},
		{"chinese", "福建邮政闽邮惠"},
		{"json", `{"name":"test","value":123}`},
		{"exact block", "1234567890abcdef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := SM4Encrypt(tt.plaintext, b64Key)
			if err != nil {
				t.Fatalf("SM4Encrypt error: %v", err)
			}
			if !strings.HasPrefix(encrypted, "|$4|") {
				t.Fatalf("encrypted should have |$4| prefix, got %q", encrypted)
			}

			decrypted, err := SM4Decrypt(encrypted, b64Key)
			if err != nil {
				t.Fatalf("SM4Decrypt error: %v", err)
			}
			if decrypted != tt.plaintext {
				t.Errorf("roundtrip failed: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestSM4EncryptSkipsAlreadyPrefixed(t *testing.T) {
	b64Key := base64.StdEncoding.EncodeToString([]byte("1234567890abcdef"))

	for _, input := range []string{"|$4|somedata", "|$|somedata"} {
		result, err := SM4Encrypt(input, b64Key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != input {
			t.Errorf("expected %q unchanged, got %q", input, result)
		}
	}
}

func TestSM4DecryptEmpty(t *testing.T) {
	result, err := SM4Decrypt("", "somekey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestSM4DecryptNoPrefixPassthrough(t *testing.T) {
	result, err := SM4Decrypt("plainvalue", "somekey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "plainvalue" {
		t.Errorf("expected passthrough, got %q", result)
	}
}

func TestSM4DecryptLegacyAESPrefix(t *testing.T) {
	rawKey := []byte("1234567890abcdef")
	b64Key := base64.StdEncoding.EncodeToString(rawKey)

	// Encrypt with AES/ECB, then prepend |$| prefix
	plain := "legacy test"
	aesEncrypted, err := Encrypt(plain, string(rawKey))
	if err != nil {
		t.Fatalf("AES Encrypt error: %v", err)
	}
	ciphertext := "|$|" + aesEncrypted

	decrypted, err := SM4Decrypt(ciphertext, b64Key)
	if err != nil {
		t.Fatalf("SM4Decrypt legacy error: %v", err)
	}
	if decrypted != plain {
		t.Errorf("legacy roundtrip failed: got %q, want %q", decrypted, plain)
	}
}
