package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	vaultPrefix = "enc:v1:"
	nonceSize   = 12 // 96-bit nonce for AES-GCM
)

// getVaultKey derives a 32-byte AES-256 key from environment or fallback
func getVaultKey() []byte {
	raw := os.Getenv("NEXUSEDGE_VAULT_KEY")
	if raw == "" {
		raw = "nexusedge-default-dev-vault-encryption-key-2026"
	}
	hash := sha256.Sum256([]byte(raw))
	return hash[:]
}

// EncryptSecret encrypts plaintext using AES-256-GCM and formats as enc:v1:<base64>
func EncryptSecret(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if strings.HasPrefix(plaintext, vaultPrefix) {
		return plaintext, nil // Already encrypted
	}

	key := getVaultKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return vaultPrefix + encoded, nil
}

// DecryptSecret decrypts enc:v1:<base64> ciphertext using AES-256-GCM.
// Plaintext strings without the prefix are returned as-is for backward compatibility.
func DecryptSecret(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if !strings.HasPrefix(ciphertext, vaultPrefix) {
		return ciphertext, nil // Plaintext backward compatibility
	}

	payload := strings.TrimPrefix(ciphertext, vaultPrefix)
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("decode vault payload: %w", err)
	}

	if len(raw) < nonceSize {
		return "", errors.New("vault payload too short")
	}

	key := getVaultKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonce, encrypted := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt vault payload: %w", err)
	}

	return string(plaintext), nil
}

// IsEncrypted returns true if the secret string has the vault envelope prefix
func IsEncrypted(secret string) bool {
	return strings.HasPrefix(secret, vaultPrefix)
}
