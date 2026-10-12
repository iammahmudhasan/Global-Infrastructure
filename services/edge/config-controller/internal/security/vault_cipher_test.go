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

func TestVaultCipher_ProductionKeyValidation(t *testing.T) {
	// 1. Missing key in production must fail
	t.Setenv("NEXUSEDGE_ENV", "production")
	t.Setenv("NEXUSEDGE_VAULT_KEY", "")

	_, err := GetVaultKey()
	if err == nil {
		t.Fatalf("expected error when NEXUSEDGE_VAULT_KEY is empty in production")
	}

	// 2. Invalid length key in production must fail
	t.Setenv("NEXUSEDGE_VAULT_KEY", "too-short")
	_, err = GetVaultKey()
	if err == nil {
		t.Fatalf("expected error when NEXUSEDGE_VAULT_KEY is invalid length in production")
	}

	// 3. Valid base64 32-byte key in production must succeed
	// 32 bytes of 'A' (0x41) base64 encoded: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
	validB64 := "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
	t.Setenv("NEXUSEDGE_VAULT_KEY", validB64)
	key, err := GetVaultKey()
	if err != nil {
		t.Fatalf("expected valid base64 key to succeed in production: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	// 4. Valid raw 32-byte key in production must succeed
	validRaw := "12345678901234567890123456789012"
	t.Setenv("NEXUSEDGE_VAULT_KEY", validRaw)
	key, err = GetVaultKey()
	if err != nil {
		t.Fatalf("expected valid raw 32-byte key to succeed in production: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
}
