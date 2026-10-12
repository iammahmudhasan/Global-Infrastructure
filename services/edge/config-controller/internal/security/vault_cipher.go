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

// GetVaultKey derives a 32-byte AES-256 key from the environment.
// In production (NEXUSEDGE_ENV=production), a valid 32-byte key or base64-encoded 32-byte key is mandatory.
func GetVaultKey() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("NEXUSEDGE_VAULT_KEY"))
	isProd := strings.EqualFold(os.Getenv("NEXUSEDGE_ENV"), "production") ||
		strings.EqualFold(os.Getenv("ENVIRONMENT"), "production") ||
		strings.EqualFold(os.Getenv("APP_ENV"), "production")

	if raw == "" {
		if isProd {
			return nil, errors.New("NEXUSEDGE_VAULT_KEY is strictly required in production environment")
		}
		raw = "nexusedge-dev-vault-encryption-key-2026-local"
	}

	// Try base64 decoding (e.g. from KMS or secret manager)
	if key, err := base64.StdEncoding.DecodeString(raw); err == nil && len(key) == 32 {
		return key, nil
	}

	// Check raw byte length
	if len(raw) == 32 {
		return []byte(raw), nil
	}

	if isProd {
		return nil, errors.New("NEXUSEDGE_VAULT_KEY in production must be either 32 raw bytes or base64-encoded 32 bytes")
	}

	// Non-production fallback uses SHA-256 derivation of dev passphrase
	hash := sha256.Sum256([]byte(raw))
	return hash[:], nil
}

// EncryptSecret encrypts plaintext using AES-256-GCM and formats as enc:v1:<base64>
func EncryptSecret(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if strings.HasPrefix(plaintext, vaultPrefix) {
		return plaintext, nil // Already encrypted
	}

	key, err := GetVaultKey()
	if err != nil {
		return "", fmt.Errorf("retrieve vault key: %w", err)
	}

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

	key, err := GetVaultKey()
	if err != nil {
		return "", fmt.Errorf("retrieve vault key: %w", err)
	}

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
