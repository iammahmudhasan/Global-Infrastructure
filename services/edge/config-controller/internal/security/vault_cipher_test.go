package security

import (
	"testing"
)

func TestVaultCipher_EncryptDecrypt(t *testing.T) {
	original := "sk-ant-api03-test-secret-key-1234567890"

	encrypted, err := EncryptSecret(original)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	if !IsEncrypted(encrypted) {
		t.Fatalf("expected encrypted string to have vault prefix, got: %s", encrypted)
	}

	if encrypted == original {
		t.Fatalf("ciphertext must not match plaintext")
	}

	// Idempotent encryption test
	encryptedAgain, err := EncryptSecret(encrypted)
	if err != nil {
		t.Fatalf("failed idempotent encrypt: %v", err)
	}
	if encryptedAgain != encrypted {
		t.Fatalf("encrypting already encrypted string should return identical string")
	}

	decrypted, err := DecryptSecret(encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if decrypted != original {
		t.Fatalf("decrypted value %q != original %q", decrypted, original)
	}

	// Plaintext fallback test
	plain, err := DecryptSecret(original)
	if err != nil {
		t.Fatalf("failed plaintext fallback: %v", err)
	}
	if plain != original {
		t.Fatalf("expected plaintext to remain unchanged")
	}

	// Empty string test
	emptyEnc, err := EncryptSecret("")
	if err != nil || emptyEnc != "" {
		t.Fatalf("empty string encryption failed: %v", err)
	}
}
