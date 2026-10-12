package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// GenesisHash represents the initial zero-block hash for a new audit log chain
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditRecord represents an immutable, cryptographically chained audit log entry.
type AuditRecord struct {
	ID           string                 `json:"id"`
	Timestamp    string                 `json:"timestamp"`
	ActorID      string                 `json:"actor_id"`
	OrgID        string                 `json:"org_id"`
	ProjectID    string                 `json:"project_id"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	ClientIP     string                 `json:"client_ip"`
	Details      map[string]interface{} `json:"details,omitempty"`
	PrevHash     string                 `json:"prev_hash"`
	Hash         string                 `json:"hash"`
}

// AuditLogger manages the append-only cryptographic audit trail.
type AuditLogger struct {
	mu       sync.RWMutex
	records  []*AuditRecord
	lastHash string
	hmacKey  []byte
}

// NewAuditLogger initializes a new tamper-evident audit logger with an HMAC signing key.
func NewAuditLogger(hmacKey []byte) *AuditLogger {
	if len(hmacKey) == 0 {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		hmacKey = key
	}
	return &AuditLogger{
		records:  make([]*AuditRecord, 0),
		lastHash: GenesisHash,
		hmacKey:  hmacKey,
	}
}

// Record appends a new audit record to the chain, computing its cryptographic hash.
func (l *AuditLogger) Record(actorID, orgID, projectID, action, resourceType, resourceID, clientIP string, details map[string]interface{}) (*AuditRecord, error) {
	if actorID == "" {
		return nil, errors.New("actor_id is required")
	}
	if action == "" {
		return nil, errors.New("action is required")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generate audit id: %w", err)
	}
	recordID := fmt.Sprintf("aud-%x", idBytes)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	prevHash := l.lastHash

	record := &AuditRecord{
		ID:           recordID,
		Timestamp:    now,
		ActorID:      actorID,
		OrgID:        orgID,
		ProjectID:    projectID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ClientIP:     clientIP,
		Details:      details,
		PrevHash:     prevHash,
	}

	hash, err := l.computeRecordHash(record)
	if err != nil {
		return nil, fmt.Errorf("compute record hash: %w", err)
	}
	record.Hash = hash

	l.records = append(l.records, record)
	l.lastHash = hash

	return record, nil
}

// computeRecordHash generates an HMAC-SHA256 signature across the canonical fields of the record.
func (l *AuditLogger) computeRecordHash(r *AuditRecord) (string, error) {
	// Canonical representation omitting the Hash field itself
	canonicalPayload := struct {
		ID           string                 `json:"id"`
		Timestamp    string                 `json:"timestamp"`
		ActorID      string                 `json:"actor_id"`
		OrgID        string                 `json:"org_id"`
		ProjectID    string                 `json:"project_id"`
		Action       string                 `json:"action"`
		ResourceType string                 `json:"resource_type"`
		ResourceID   string                 `json:"resource_id"`
		ClientIP     string                 `json:"client_ip"`
		Details      map[string]interface{} `json:"details,omitempty"`
		PrevHash     string                 `json:"prev_hash"`
	}{
		ID:           r.ID,
		Timestamp:    r.Timestamp,
		ActorID:      r.ActorID,
		OrgID:        r.OrgID,
		ProjectID:    r.ProjectID,
		Action:       r.Action,
		ResourceType: r.ResourceType,
		ResourceID:   r.ResourceID,
		ClientIP:     r.ClientIP,
		Details:      r.Details,
		PrevHash:     r.PrevHash,
	}

	raw, err := json.Marshal(canonicalPayload)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, l.hmacKey)
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyChain iterates through all recorded audit logs and cryptographically verifies the hash chain.
func (l *AuditLogger) VerifyChain() (bool, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	expectedPrevHash := GenesisHash
	for i, record := range l.records {
		if record.PrevHash != expectedPrevHash {
			return false, fmt.Errorf("audit chain broken at index %d: expected prev_hash %s, got %s", i, expectedPrevHash, record.PrevHash)
		}

		expectedHash, err := l.computeRecordHash(record)
		if err != nil {
			return false, fmt.Errorf("verify record %d: %w", i, err)
		}

		if record.Hash != expectedHash {
			return false, fmt.Errorf("tamper detected at index %d: record %s hash altered", i, record.ID)
		}

		expectedPrevHash = record.Hash
	}

	return true, nil
}

// GetRecords returns a copy of all current audit records.
func (l *AuditLogger) GetRecords() []*AuditRecord {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]*AuditRecord, len(l.records))
	copy(out, l.records)
	return out
}
