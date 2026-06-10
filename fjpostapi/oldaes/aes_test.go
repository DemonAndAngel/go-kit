package oldaes

import (
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	// 16-byte key (AES-128), matching Java's SecretKeySpec usage.
	key := "1234567890abcdef"

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple", "hello world"},
		{"chinese", "福建邮政闽邮惠"},
		{"empty", ""},
		{"exact block", "1234567890123456"},
		{"json", `{"name":"test","value":123}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(tt.plaintext, key)
			if err != nil {
				t.Fatalf("Encrypt error: %v", err)
			}

			decrypted, err := Decrypt(encrypted, key)
			if err != nil {
				t.Fatalf("Decrypt error: %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("roundtrip failed: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestDecryptEmpty(t *testing.T) {
	result, err := Decrypt("", "1234567890abcdef")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestInvalidKeyLength(t *testing.T) {
	_, err := Encrypt("hello", "short")
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}
