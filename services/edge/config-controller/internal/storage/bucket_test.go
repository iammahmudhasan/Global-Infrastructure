package storage

import (
	"bytes"
	"testing"
)

func TestStorageManager_BucketLifecycle(t *testing.T) {
	mgr := NewManager()

	// 1. Create valid bucket
	b, err := mgr.CreateBucket(
		"tenant-alpha", "proj-alpha",
		"alpha-checkpoints",
		PolicyBangladeshOnly,
		TopologySingleRegionNVMe,
		"ap-south-2",
		1024*1024,
	)
	if err != nil {
		t.Fatalf("expected successful bucket creation, got %v", err)
	}
	if b.Name != "alpha-checkpoints" {
		t.Errorf("expected bucket name alpha-checkpoints, got %s", b.Name)
	}
	if b.SovereigntyPolicy != PolicyBangladeshOnly {
		t.Errorf("expected BD_ONLY policy, got %s", b.SovereigntyPolicy)
	}

	// 2. Reject duplicate bucket name
	_, err = mgr.CreateBucket(
		"tenant-beta", "proj-beta",
		"alpha-checkpoints",
		PolicyGlobalRedundant,
		TopologySingleRegionNVMe,
		"us-east-1",
		1024*1024,
	)
	if err != ErrBucketAlreadyExists {
		t.Errorf("expected ErrBucketAlreadyExists, got %v", err)
	}

	// 3. Reject invalid bucket names
	invalidNames := []string{"", "a", "ab", "UPPERCASE", "invalid_underscores", "has..dots", "-start-hyphen", "end-hyphen-"}
	for _, inv := range invalidNames {
		_, err := mgr.CreateBucket("tenant-alpha", "proj-alpha", inv, PolicyGlobalRedundant, TopologySingleRegionNVMe, "us-east-1", 1024)
		if err != ErrInvalidBucketName {
			t.Errorf("expected ErrInvalidBucketName for %q, got %v", inv, err)
		}
	}

	// 4. Multi-tenant isolation: tenant-beta cannot access tenant-alpha's bucket
	_, err = mgr.GetBucket("tenant-beta", "proj-beta", "alpha-checkpoints")
	if err != ErrUnauthorizedTenant {
		t.Errorf("expected ErrUnauthorizedTenant, got %v", err)
	}

	// 5. Tenant-alpha can access their bucket
	fetched, err := mgr.GetBucket("tenant-alpha", "proj-alpha", "alpha-checkpoints")
	if err != nil || fetched.Name != "alpha-checkpoints" {
		t.Errorf("expected successful get bucket, got %v", err)
	}
}

func TestStorageManager_ObjectLifecycleAndSovereignty(t *testing.T) {
	mgr := NewManager()

	// Create a BD-Sovereign bucket with 1 KB quota
	_, err := mgr.CreateBucket(
		"tenant-bank", "proj-bank",
		"bd-sovereign-vault",
		PolicyBangladeshOnly,
		TopologySingleRegionNVMe,
		"ap-south-2",
		1024, // 1 KB quota
	)
	if err != nil {
		t.Fatalf("failed to create bucket: %v", err)
	}

	payload := []byte("confidential banking ledger payload")

	// 1. Put Object
	meta, err := mgr.PutObject("tenant-bank", "proj-bank", "bd-sovereign-vault", "ledger/2026-10.dat", payload, "application/octet-stream")
	if err != nil {
		t.Fatalf("failed to put object: %v", err)
	}
	if meta.Key != "ledger/2026-10.dat" {
		t.Errorf("expected key ledger/2026-10.dat, got %s", meta.Key)
	}
	if meta.SovereignJurisdiction != "BD" {
		t.Errorf("expected jurisdiction BD, got %s", meta.SovereignJurisdiction)
	}
	if meta.SizeBytes != int64(len(payload)) {
		t.Errorf("expected size %d, got %d", len(payload), meta.SizeBytes)
	}

	// 2. Sovereign Export Enforcement: export to US must be prohibited
	_, _, err = mgr.GetObject("tenant-bank", "proj-bank", "bd-sovereign-vault", "ledger/2026-10.dat", "US")
	if err != ErrSovereignExportProhibited {
		t.Errorf("expected ErrSovereignExportProhibited when exporting BD data to US, got %v", err)
	}

	// 3. Sovereign Access inside BD is allowed
	data, fetchedMeta, err := mgr.GetObject("tenant-bank", "proj-bank", "bd-sovereign-vault", "ledger/2026-10.dat", "BD")
	if err != nil {
		t.Fatalf("expected successful get inside BD, got %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("payload mismatch: expected %q, got %q", payload, data)
	}
	if fetchedMeta.SHA256Checksum != meta.SHA256Checksum {
		t.Errorf("checksum mismatch")
	}

	// 4. Quota enforcement: try putting a 2 KB object (quota is 1 KB)
	largePayload := make([]byte, 2048)
	_, err = mgr.PutObject("tenant-bank", "proj-bank", "bd-sovereign-vault", "large.dat", largePayload, "application/octet-stream")
	if err != ErrBucketQuotaExceeded {
		t.Errorf("expected ErrBucketQuotaExceeded, got %v", err)
	}

	// 5. Bucket cannot be deleted while containing objects
	err = mgr.DeleteBucket("tenant-bank", "proj-bank", "bd-sovereign-vault")
	if err != ErrBucketNotEmpty {
		t.Errorf("expected ErrBucketNotEmpty, got %v", err)
	}

	// 6. Delete object and delete bucket
	err = mgr.DeleteObject("tenant-bank", "proj-bank", "bd-sovereign-vault", "ledger/2026-10.dat")
	if err != nil {
		t.Fatalf("expected successful object deletion, got %v", err)
	}

	err = mgr.DeleteBucket("tenant-bank", "proj-bank", "bd-sovereign-vault")
	if err != nil {
		t.Fatalf("expected successful bucket deletion after empty, got %v", err)
	}
}
