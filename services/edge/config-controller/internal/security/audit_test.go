package security_test

import (
	"sync"
	"testing"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/security"
)

func TestAuditLogger_ChainIntegrity(t *testing.T) {
	hmacKey := []byte("nexusedge-audit-hmac-secret-key-32b")
	logger := security.NewAuditLogger(hmacKey)

	// 1. Record series of administrative actions
	r1, err := logger.Record("admin-user-01", "org-nexus", "proj-core", "domain.create", "domain", "dom-101", "192.0.2.1", map[string]interface{}{"hostname": "api.nexus.io"})
	if err != nil {
		t.Fatalf("failed to record r1: %v", err)
	}
	if r1.PrevHash != security.GenesisHash {
		t.Fatalf("r1 prev_hash must be GenesisHash, got %s", r1.PrevHash)
	}

	r2, err := logger.Record("admin-user-01", "org-nexus", "proj-core", "provider.save", "ai_provider", "prov-cw", "192.0.2.1", map[string]interface{}{"provider": "coreweave"})
	if err != nil {
		t.Fatalf("failed to record r2: %v", err)
	}
	if r2.PrevHash != r1.Hash {
		t.Fatalf("r2 prev_hash must link to r1 hash: %s != %s", r2.PrevHash, r1.Hash)
	}

	r3, err := logger.Record("system-agent", "org-nexus", "proj-core", "waf.block", "security_event", "sec-99", "203.0.113.5", map[string]interface{}{"rule": "SQLI_IN_URI"})
	if err != nil {
		t.Fatalf("failed to record r3: %v", err)
	}
	if r3.PrevHash != r2.Hash {
		t.Fatalf("r3 prev_hash must link to r2 hash")
	}

	// 2. Verify complete chain validity
	valid, err := logger.VerifyChain()
	if err != nil || !valid {
		t.Fatalf("expected valid chain, got valid=%v, err=%v", valid, err)
	}

	records := logger.GetRecords()
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}
}

func TestAuditLogger_TamperDetection(t *testing.T) {
	hmacKey := []byte("nexusedge-audit-hmac-secret-key-32b")
	logger := security.NewAuditLogger(hmacKey)

	_, _ = logger.Record("actor-1", "org-1", "proj-1", "action-1", "res-1", "id-1", "127.0.0.1", nil)
	r2, _ := logger.Record("actor-2", "org-1", "proj-1", "action-2", "res-2", "id-2", "127.0.0.1", nil)
	_, _ = logger.Record("actor-3", "org-1", "proj-1", "action-3", "res-3", "id-3", "127.0.0.1", nil)

	// Tamper with record r2's Action maliciously
	r2.Action = "malicious_covert_action"

	valid, err := logger.VerifyChain()
	if valid || err == nil {
		t.Fatalf("expected tamper detection to fail chain verification, but passed")
	}
}

func TestAuditLogger_ConcurrentSafety(t *testing.T) {
	logger := security.NewAuditLogger(nil)
	var wg sync.WaitGroup
	numWorkers := 20

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			_, _ = logger.Record("worker", "org", "proj", "ping", "worker", "id", "127.0.0.1", nil)
		}(i)
	}
	wg.Wait()

	records := logger.GetRecords()
	if len(records) != numWorkers {
		t.Fatalf("expected %d records from concurrent workers, got %d", numWorkers, len(records))
	}

	valid, err := logger.VerifyChain()
	if err != nil || !valid {
		t.Fatalf("concurrent chain verification failed: %v", err)
	}
}

func TestAuditLogger_RollbackOnFailure(t *testing.T) {
	hmacKey := []byte("nexusedge-audit-hmac-secret-key-32b")
	logger := security.NewAuditLogger(hmacKey)

	r1, err := logger.Record("admin", "org-1", "proj-1", "domain.create", "domain", "dom-1", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("failed to record r1: %v", err)
	}

	r2, err := logger.Record("admin", "org-1", "proj-1", "domain.update", "domain", "dom-1", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("failed to record r2: %v", err)
	}

	if logger.LastHash() != r2.Hash {
		t.Fatalf("expected lastHash %s, got %s", r2.Hash, logger.LastHash())
	}

	// Simulate failure in database persistence: rollback r2
	logger.RollbackLastRecord(r2.ID)

	records := logger.GetRecords()
	if len(records) != 1 {
		t.Fatalf("expected 1 record after rollback, got %d", len(records))
	}
	if records[0].ID != r1.ID {
		t.Fatalf("expected remaining record to be r1, got %s", records[0].ID)
	}
	if logger.LastHash() != r1.Hash {
		t.Fatalf("expected lastHash to be restored to r1.Hash (%s), got %s", r1.Hash, logger.LastHash())
	}

	valid, err := logger.VerifyChain()
	if !valid || err != nil {
		t.Fatalf("chain must remain valid after rollback: %v", err)
	}
}
