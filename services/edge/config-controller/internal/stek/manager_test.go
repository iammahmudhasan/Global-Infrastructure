package stek

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestEnsureKeys_GeneratesKeysAndSDS(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "stek-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, 0, 1*time.Hour)
	if err := mgr.EnsureKeys(); err != nil {
		t.Fatalf("EnsureKeys failed: %v", err)
	}

	curKey, prevKey, lastRot := mgr.GetKeys()
	if len(curKey) != KeySize {
		t.Fatalf("expected current key length %d, got %d", KeySize, len(curKey))
	}
	if len(prevKey) != KeySize {
		t.Fatalf("expected previous key length %d, got %d", KeySize, len(prevKey))
	}
	if lastRot.IsZero() {
		t.Fatalf("expected non-zero lastRotated timestamp")
	}

	// Verify key files on disk
	curData, err := os.ReadFile(filepath.Join(tmpDir, "stek", "current.key"))
	if err != nil || len(curData) != KeySize {
		t.Fatalf("failed to read current.key from disk: err=%v, len=%d", err, len(curData))
	}

	prevData, err := os.ReadFile(filepath.Join(tmpDir, "stek", "previous.key"))
	if err != nil || len(prevData) != KeySize {
		t.Fatalf("failed to read previous.key from disk: err=%v, len=%d", err, len(prevData))
	}

	// Verify sds_stek.json on disk
	sdsBytes, err := os.ReadFile(filepath.Join(tmpDir, "sds_stek.json"))
	if err != nil {
		t.Fatalf("failed to read sds_stek.json: %v", err)
	}

	var sdsPayload struct {
		Resources []struct {
			Type              string `json:"@type"`
			Name              string `json:"name"`
			SessionTicketKeys struct {
				Keys []struct {
					Filename string `json:"filename"`
				} `json:"keys"`
			} `json:"session_ticket_keys"`
		} `json:"resources"`
	}

	if err := json.Unmarshal(sdsBytes, &sdsPayload); err != nil {
		t.Fatalf("failed to unmarshal sds_stek.json: %v", err)
	}

	if len(sdsPayload.Resources) != 1 {
		t.Fatalf("expected 1 resource in sds_stek.json, got %d", len(sdsPayload.Resources))
	}
	res := sdsPayload.Resources[0]
	if res.Name != "dynamic_session_ticket_keys" {
		t.Fatalf("expected resource name 'dynamic_session_ticket_keys', got %s", res.Name)
	}
	if len(res.SessionTicketKeys.Keys) != 2 {
		t.Fatalf("expected 2 keys in sds_stek.json, got %d", len(res.SessionTicketKeys.Keys))
	}
}

func TestEnsureKeys_PreservesExistingKeys(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "stek-preserve-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	stekDir := filepath.Join(tmpDir, "stek")
	_ = os.MkdirAll(stekDir, 0755)

	fixedCur := make([]byte, KeySize)
	for i := range fixedCur {
		fixedCur[i] = 0xAA
	}
	fixedPrev := make([]byte, KeySize)
	for i := range fixedPrev {
		fixedPrev[i] = 0xBB
	}

	_ = os.WriteFile(filepath.Join(stekDir, "current.key"), fixedCur, 0600)
	_ = os.WriteFile(filepath.Join(stekDir, "previous.key"), fixedPrev, 0600)

	mgr := NewManager(tmpDir, 0, 1*time.Hour)
	if err := mgr.EnsureKeys(); err != nil {
		t.Fatalf("EnsureKeys failed: %v", err)
	}

	curKey, prevKey, _ := mgr.GetKeys()
	if string(curKey) != string(fixedCur) {
		t.Fatalf("expected current key to be preserved")
	}
	if string(prevKey) != string(fixedPrev) {
		t.Fatalf("expected previous key to be preserved")
	}
}

func TestRotateKeys_ShiftsCurrentToPrevious(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "stek-rotate-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, 0, 1*time.Hour)
	if err := mgr.EnsureKeys(); err != nil {
		t.Fatalf("EnsureKeys failed: %v", err)
	}

	initialCur, _, _ := mgr.GetKeys()

	if err := mgr.RotateKeys(); err != nil {
		t.Fatalf("RotateKeys failed: %v", err)
	}

	newCur, newPrev, _ := mgr.GetKeys()

	if string(newCur) == string(initialCur) {
		t.Fatalf("expected new current key to differ from initial current key")
	}
	if string(newPrev) != string(initialCur) {
		t.Fatalf("expected previous key to be old current key after rotation")
	}
}

func TestSetKeys_ValidatesLengthAndWrites(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "stek-set-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, 0, 1*time.Hour)

	invalidShort := make([]byte, 32)
	valid := make([]byte, KeySize)

	if err := mgr.SetKeys(invalidShort, valid); err != ErrInvalidKeySize {
		t.Fatalf("expected ErrInvalidKeySize, got %v", err)
	}
	if err := mgr.SetKeys(valid, invalidShort); err != ErrInvalidKeySize {
		t.Fatalf("expected ErrInvalidKeySize, got %v", err)
	}

	for i := range valid {
		valid[i] = byte(i)
	}
	validPrev := make([]byte, KeySize)
	for i := range validPrev {
		validPrev[i] = byte(KeySize - i)
	}

	if err := mgr.SetKeys(valid, validPrev); err != nil {
		t.Fatalf("SetKeys failed: %v", err)
	}

	cur, prev, _ := mgr.GetKeys()
	if string(cur) != string(valid) || string(prev) != string(validPrev) {
		t.Fatalf("keys were not updated properly")
	}
}

func TestConcurrency_GetAndRotate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "stek-concurrent-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, 0, 10*time.Millisecond)
	_ = mgr.EnsureKeys()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if id%5 == 0 && j%10 == 0 {
					_ = mgr.RotateKeys()
				} else {
					cur, prev, _ := mgr.GetKeys()
					if len(cur) != KeySize || len(prev) != KeySize {
						t.Errorf("corrupted key in reader: cur=%d, prev=%d", len(cur), len(prev))
					}
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestStartStopLifecycle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "stek-lifecycle-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, 0, 10*time.Millisecond)
	_ = mgr.EnsureKeys()

	mgr.Start()
	time.Sleep(30 * time.Millisecond)
	mgr.Stop()
}
