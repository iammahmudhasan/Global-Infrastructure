package stek

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	// KeySize is exactly 80 bytes as mandated by BoringSSL and Envoy TLS session ticket specification.
	// 16 bytes key name + 32 bytes HMAC-SHA256 key + 32 bytes AES-256-GCM/CBC key.
	KeySize = 80

	// DefaultRotationInterval is 12 hours.
	DefaultRotationInterval = 12 * time.Hour

	// DefaultKeyLifetime is 48 hours for graceful decryption transition.
	DefaultKeyLifetime = 48 * time.Hour
)

var (
	ErrInvalidKeySize = errors.New("stek key must be exactly 80 bytes")
)

// Manager handles the cryptographic generation, file-based persistence,
// Envoy SDS JSON formatting, and automated rotation of Session Ticket Encryption Keys (STEK).
type Manager struct {
	mu          sync.RWMutex
	certsDir    string
	certsGid    int
	interval    time.Duration
	stopCh      chan struct{}
	stopped     bool
	currentKey  []byte
	previousKey []byte
	lastRotated time.Time
}

// NewManager creates a new STEK Manager.
func NewManager(certsDir string, certsGid int, interval time.Duration) *Manager {
	if interval <= 0 {
		interval = DefaultRotationInterval
	}
	return &Manager{
		certsDir: certsDir,
		certsGid: certsGid,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// SetCertsDir configures the directory where Envoy certificate and STEK secrets are stored.
func (m *Manager) SetCertsDir(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certsDir = dir
}

// EnsureKeys verifies that valid 80-byte STEK keys exist on disk and in memory.
// If missing or corrupted, fresh cryptographically secure keys are generated and synced to SDS.
func (m *Manager) EnsureKeys() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.certsDir == "" {
		return fmt.Errorf("certsDir is not configured")
	}

	stekDir := filepath.Join(m.certsDir, "stek")
	if err := os.MkdirAll(stekDir, 0755); err != nil {
		return fmt.Errorf("failed to create stek directory %s: %w", stekDir, err)
	}

	currentPath := filepath.Join(stekDir, "current.key")
	previousPath := filepath.Join(stekDir, "previous.key")

	curKey, errCur := os.ReadFile(currentPath)
	prevKey, errPrev := os.ReadFile(previousPath)

	needsWrite := false

	if errCur != nil || len(curKey) != KeySize {
		newCur := make([]byte, KeySize)
		if _, err := io.ReadFull(rand.Reader, newCur); err != nil {
			return fmt.Errorf("failed to generate random 80-byte current STEK key: %w", err)
		}
		curKey = newCur
		needsWrite = true
	}

	if errPrev != nil || len(prevKey) != KeySize {
		newPrev := make([]byte, KeySize)
		if _, err := io.ReadFull(rand.Reader, newPrev); err != nil {
			return fmt.Errorf("failed to generate random 80-byte previous STEK key: %w", err)
		}
		prevKey = newPrev
		needsWrite = true
	}

	m.currentKey = curKey
	m.previousKey = prevKey
	m.lastRotated = time.Now().UTC()

	if needsWrite {
		if err := m.writeKeyFile(currentPath, m.currentKey); err != nil {
			return err
		}
		if err := m.writeKeyFile(previousPath, m.previousKey); err != nil {
			return err
		}
		if err := m.syncSDSLocked(); err != nil {
			return err
		}
	} else {
		// Ensure sds_stek.json is in place even if keys existed
		sdsPath := filepath.Join(m.certsDir, "sds_stek.json")
		if _, err := os.Stat(sdsPath); os.IsNotExist(err) {
			if err := m.syncSDSLocked(); err != nil {
				return err
			}
		}
	}

	return nil
}

// RotateKeys rotates the session ticket keys by shifting current -> previous,
// generating a fresh 80-byte current key, and atomically updating sds_stek.json.
func (m *Manager) RotateKeys() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.certsDir == "" {
		return fmt.Errorf("certsDir is not configured")
	}

	stekDir := filepath.Join(m.certsDir, "stek")
	if err := os.MkdirAll(stekDir, 0755); err != nil {
		return fmt.Errorf("failed to create stek directory %s: %w", stekDir, err)
	}

	newKey := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return fmt.Errorf("failed to generate random 80-byte STEK key: %w", err)
	}

	// Move current to previous
	if len(m.currentKey) == KeySize {
		m.previousKey = m.currentKey
	} else {
		m.previousKey = make([]byte, KeySize)
		_, _ = io.ReadFull(rand.Reader, m.previousKey)
	}
	m.currentKey = newKey
	m.lastRotated = time.Now().UTC()

	currentPath := filepath.Join(stekDir, "current.key")
	previousPath := filepath.Join(stekDir, "previous.key")

	if err := m.writeKeyFile(currentPath, m.currentKey); err != nil {
		return err
	}
	if err := m.writeKeyFile(previousPath, m.previousKey); err != nil {
		return err
	}

	if err := m.syncSDSLocked(); err != nil {
		return err
	}

	log.Printf("[INFO] Rotated STEK TLS session ticket keys (new key generated, previous key preserved for grace period)")
	return nil
}

// SetKeys allows the control plane to synchronize authoritative keys across distributed PoPs.
func (m *Manager) SetKeys(current, previous []byte) error {
	if len(current) != KeySize || len(previous) != KeySize {
		return ErrInvalidKeySize
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.currentKey = make([]byte, KeySize)
	copy(m.currentKey, current)

	m.previousKey = make([]byte, KeySize)
	copy(m.previousKey, previous)
	m.lastRotated = time.Now().UTC()

	if m.certsDir != "" {
		stekDir := filepath.Join(m.certsDir, "stek")
		if err := os.MkdirAll(stekDir, 0755); err != nil {
			return err
		}
		if err := m.writeKeyFile(filepath.Join(stekDir, "current.key"), m.currentKey); err != nil {
			return err
		}
		if err := m.writeKeyFile(filepath.Join(stekDir, "previous.key"), m.previousKey); err != nil {
			return err
		}
		if err := m.syncSDSLocked(); err != nil {
			return err
		}
	}

	return nil
}

// GetKeys returns defensive copies of the current and previous STEK keys and the last rotation timestamp.
func (m *Manager) GetKeys() (current, previous []byte, lastRotated time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cur := make([]byte, len(m.currentKey))
	copy(cur, m.currentKey)

	prev := make([]byte, len(m.previousKey))
	copy(prev, m.previousKey)

	return cur, prev, m.lastRotated
}

// GetKeysBase64 returns the base64-encoded representation of the STEK keys for API transmission.
func (m *Manager) GetKeysBase64() (curB64, prevB64 string, lastRotated time.Time) {
	cur, prev, rotated := m.GetKeys()
	return base64.StdEncoding.EncodeToString(cur), base64.StdEncoding.EncodeToString(prev), rotated
}

// Start runs the periodic key rotation loop in the background.
func (m *Manager) Start() {
	m.mu.Lock()
	if m.stopped {
		m.stopCh = make(chan struct{})
		m.stopped = false
	}
	m.mu.Unlock()

	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := m.RotateKeys(); err != nil {
					log.Printf("[ERROR] Failed to rotate STEK keys: %v", err)
				}
			case <-m.stopCh:
				return
			}
		}
	}()
}

// Stop gracefully stops the background rotation loop.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.stopped && m.stopCh != nil {
		close(m.stopCh)
		m.stopped = true
	}
}

func (m *Manager) writeKeyFile(path string, keyData []byte) error {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, keyData, 0640); err != nil {
		return fmt.Errorf("failed to write key file %s: %w", tmpPath, err)
	}

	if m.certsGid > 0 && runtime.GOOS != "windows" && runtime.GOOS != "plan9" {
		_ = os.Chown(tmpPath, -1, m.certsGid)
	}
	_ = os.Chmod(tmpPath, 0640)

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename key file to %s: %w", path, err)
	}

	return nil
}

func (m *Manager) syncSDSLocked() error {
	sdsPath := filepath.Join(m.certsDir, "sds_stek.json")

	sdsPayload := map[string]interface{}{
		"resources": []map[string]interface{}{
			{
				"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
				"name":  "dynamic_session_ticket_keys",
				"session_ticket_keys": map[string]interface{}{
					"keys": []map[string]string{
						{
							"filename": "/etc/envoy/certs/stek/current.key",
						},
						{
							"filename": "/etc/envoy/certs/stek/previous.key",
						},
					},
				},
			},
		},
	}

	data, err := json.MarshalIndent(sdsPayload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sds_stek payload: %w", err)
	}

	tmpPath := sdsPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write sds_stek tmp file: %w", err)
	}

	if m.certsGid > 0 && runtime.GOOS != "windows" && runtime.GOOS != "plan9" {
		_ = os.Chown(tmpPath, -1, m.certsGid)
	}
	_ = os.Chmod(tmpPath, 0644)

	if err := os.Rename(tmpPath, sdsPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename sds_stek file to %s: %w", sdsPath, err)
	}

	return nil
}
