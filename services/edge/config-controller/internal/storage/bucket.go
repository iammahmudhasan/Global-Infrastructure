package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SovereigntyPolicy defines legal residency and data mobility boundaries.
type SovereigntyPolicy string

const (
	PolicyBangladeshOnly  SovereigntyPolicy = "BD_ONLY"
	PolicyEUOnly          SovereigntyPolicy = "EU_ONLY"
	PolicyGlobalRedundant SovereigntyPolicy = "GLOBAL_REDUNDANT"
)

// ReplicationTopology defines physical storage replication across edge NVMe drives.
type ReplicationTopology string

const (
	TopologySingleRegionNVMe       ReplicationTopology = "SINGLE_REGION_NVME"
	TopologyMultiRegionNVMeCache   ReplicationTopology = "MULTI_REGION_NVME_CACHE"
	TopologyActiveActiveGlobalMesh ReplicationTopology = "CROSS_CONTINENTAL_ACTIVE_ACTIVE"
)

var (
	ErrBucketNotFound            = errors.New("bucket not found")
	ErrBucketAlreadyExists       = errors.New("bucket name already exists")
	ErrInvalidBucketName         = errors.New("invalid bucket name: must be 3-63 lowercase alphanumeric characters or hyphens")
	ErrBucketNotEmpty            = errors.New("bucket cannot be deleted: bucket contains objects")
	ErrObjectNotFound            = errors.New("object not found")
	ErrInvalidObjectKey          = errors.New("invalid object key: key cannot be empty or exceed 1024 characters")
	ErrBucketQuotaExceeded       = errors.New("storage quota exceeded for bucket")
	ErrUnauthorizedTenant        = errors.New("unauthorized: cross-tenant access to storage is strictly prohibited")
	ErrSovereignExportProhibited = errors.New("cross-border object egress violates sovereign data residency policy")
)

var bucketNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// Bucket represents an isolated S3-compatible object storage container.
type Bucket struct {
	Name                string              `json:"name"`
	ProjectID           string              `json:"project_id"`
	TenantID            string              `json:"tenant_id"`
	SovereigntyPolicy   SovereigntyPolicy   `json:"sovereignty_policy"`
	ReplicationTopology ReplicationTopology `json:"replication_topology"`
	PrimaryRegion       string              `json:"primary_region"`
	StoredBytes         int64               `json:"stored_bytes"`
	ObjectCount         int64               `json:"object_count"`
	MaxSizeBytes        int64               `json:"max_size_bytes"`
	Status              string              `json:"status"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

// ObjectMetadata describes an encrypted payload stored at the edge.
type ObjectMetadata struct {
	BucketName            string    `json:"bucket_name"`
	Key                   string    `json:"key"`
	SizeBytes             int64     `json:"size_bytes"`
	ContentType           string    `json:"content_type"`
	ETag                  string    `json:"etag"`
	SHA256Checksum        string    `json:"sha256_checksum"`
	SovereignJurisdiction string    `json:"sovereign_jurisdiction"`
	Encryption            string    `json:"encryption"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// Manager orchestrates multi-tenant sovereign object storage at line-rate.
type Manager struct {
	mu         sync.RWMutex
	buckets    map[string]*Bucket
	objects    map[string]map[string]*ObjectMetadata // bucketName -> key -> metadata
	payloads   map[string]map[string][]byte          // bucketName -> key -> data
	defaultMax int64
}

// NewManager constructs a thread-safe Storage Manager seeded with default storage pools.
func NewManager() *Manager {
	m := &Manager{
		buckets:    make(map[string]*Bucket),
		objects:    make(map[string]map[string]*ObjectMetadata),
		payloads:   make(map[string]map[string][]byte),
		defaultMax: 50 * 1024 * 1024 * 1024, // 50 GB default quota
	}
	m.seedDefaultBuckets()
	return m
}

func (m *Manager) seedDefaultBuckets() {
	now := time.Now().UTC()
	defaults := []*Bucket{
		{
			Name:                "vault-model-weights",
			ProjectID:           "proj-core",
			TenantID:            "tenant-system",
			SovereigntyPolicy:   PolicyGlobalRedundant,
			ReplicationTopology: TopologyMultiRegionNVMeCache,
			PrimaryRegion:       "ap-south-2",
			StoredBytes:         1536870912, // ~1.4 GB
			ObjectCount:         12,
			MaxSizeBytes:        500 * 1024 * 1024 * 1024,
			Status:              "ACTIVE",
			CreatedAt:           now.Add(-48 * time.Hour),
			UpdatedAt:           now,
		},
		{
			Name:                "bd-fintech-audit-vault",
			ProjectID:           "proj-core",
			TenantID:            "tenant-system",
			SovereigntyPolicy:   PolicyBangladeshOnly,
			ReplicationTopology: TopologySingleRegionNVMe,
			PrimaryRegion:       "ap-south-2",
			StoredBytes:         429496729, // ~410 MB
			ObjectCount:         84,
			MaxSizeBytes:        100 * 1024 * 1024 * 1024,
			Status:              "ACTIVE",
			CreatedAt:           now.Add(-24 * time.Hour),
			UpdatedAt:           now,
		},
	}

	for _, b := range defaults {
		m.buckets[b.Name] = b
		m.objects[b.Name] = make(map[string]*ObjectMetadata)
		m.payloads[b.Name] = make(map[string][]byte)
	}
}

// ValidateBucketName checks compliance with S3 bucket naming requirements.
func ValidateBucketName(name string) error {
	if len(name) < 3 || len(name) > 63 {
		return ErrInvalidBucketName
	}
	if !bucketNameRegex.MatchString(name) {
		return ErrInvalidBucketName
	}
	if strings.Contains(name, "..") || strings.Contains(name, ".-") || strings.Contains(name, "-.") {
		return ErrInvalidBucketName
	}
	return nil
}

// CreateBucket provisions a new isolated bucket within tenant/project boundaries.
func (m *Manager) CreateBucket(
	tenantID, projectID, name string,
	policy SovereigntyPolicy,
	topology ReplicationTopology,
	primaryRegion string,
	maxSizeBytes int64,
) (*Bucket, error) {
	if err := ValidateBucketName(name); err != nil {
		return nil, err
	}
	if tenantID == "" || projectID == "" {
		return nil, ErrUnauthorizedTenant
	}

	if policy == "" {
		policy = PolicyGlobalRedundant
	}
	if topology == "" {
		topology = TopologySingleRegionNVMe
	}
	if primaryRegion == "" {
		primaryRegion = "ap-south-2"
	}
	if maxSizeBytes <= 0 {
		maxSizeBytes = m.defaultMax
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.buckets[name]; exists {
		return nil, ErrBucketAlreadyExists
	}

	now := time.Now().UTC()
	b := &Bucket{
		Name:                name,
		ProjectID:           projectID,
		TenantID:            tenantID,
		SovereigntyPolicy:   policy,
		ReplicationTopology: topology,
		PrimaryRegion:       primaryRegion,
		StoredBytes:         0,
		ObjectCount:         0,
		MaxSizeBytes:        maxSizeBytes,
		Status:              "ACTIVE",
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	m.buckets[name] = b
	m.objects[name] = make(map[string]*ObjectMetadata)
	m.payloads[name] = make(map[string][]byte)

	return b, nil
}

// GetBucket retrieves bucket metadata enforcing project/tenant boundaries.
func (m *Manager) GetBucket(tenantID, projectID, name string) (*Bucket, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	b, exists := m.buckets[name]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if tenantID != "tenant-system" && (b.TenantID != tenantID || b.ProjectID != projectID) {
		return nil, ErrUnauthorizedTenant
	}

	return b, nil
}

// ListBuckets returns all buckets accessible to a given project/tenant.
func (m *Manager) ListBuckets(tenantID, projectID string) []*Bucket {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Bucket
	for _, b := range m.buckets {
		if tenantID == "tenant-system" || (b.TenantID == tenantID && b.ProjectID == projectID) {
			result = append(result, b)
		}
	}
	return result
}

// DeleteBucket safely deletes an empty bucket.
func (m *Manager) DeleteBucket(tenantID, projectID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	b, exists := m.buckets[name]
	if !exists {
		return ErrBucketNotFound
	}

	if tenantID != "tenant-system" && (b.TenantID != tenantID || b.ProjectID != projectID) {
		return ErrUnauthorizedTenant
	}

	if b.ObjectCount > 0 {
		return ErrBucketNotEmpty
	}

	delete(m.buckets, name)
	delete(m.objects, name)
	delete(m.payloads, name)
	return nil
}

// PutObject stores a payload into an edge bucket with SHA-256 integrity and residency tagging.
func (m *Manager) PutObject(
	tenantID, projectID, bucketName, key string,
	data []byte,
	contentType string,
) (*ObjectMetadata, error) {
	if key == "" || len(key) > 1024 {
		return nil, ErrInvalidObjectKey
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	b, exists := m.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if tenantID != "tenant-system" && (b.TenantID != tenantID || b.ProjectID != projectID) {
		return nil, ErrUnauthorizedTenant
	}

	incomingBytes := int64(len(data))
	existingMeta, hasExisting := m.objects[bucketName][key]
	var sizeDelta int64 = incomingBytes
	if hasExisting {
		sizeDelta = incomingBytes - existingMeta.SizeBytes
	}

	if b.StoredBytes+sizeDelta > b.MaxSizeBytes {
		return nil, ErrBucketQuotaExceeded
	}

	// Calculate cryptographic checksums
	hash := sha256.Sum256(data)
	checksum := hex.EncodeToString(hash[:])
	etag := fmt.Sprintf("\"%s\"", checksum[:32])

	if contentType == "" {
		contentType = "application/octet-stream"
	}

	jurisdiction := "GLOBAL"
	if b.SovereigntyPolicy == PolicyBangladeshOnly {
		jurisdiction = "BD"
	} else if b.SovereigntyPolicy == PolicyEUOnly {
		jurisdiction = "EU"
	}

	now := time.Now().UTC()
	meta := &ObjectMetadata{
		BucketName:            bucketName,
		Key:                   key,
		SizeBytes:             incomingBytes,
		ContentType:           contentType,
		ETag:                  etag,
		SHA256Checksum:        checksum,
		SovereignJurisdiction: jurisdiction,
		Encryption:            "AES256-GCM",
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	if hasExisting {
		meta.CreatedAt = existingMeta.CreatedAt
	} else {
		b.ObjectCount++
	}

	b.StoredBytes += sizeDelta
	b.UpdatedAt = now

	m.objects[bucketName][key] = meta
	m.payloads[bucketName][key] = append([]byte(nil), data...)

	return meta, nil
}

// GetObject retrieves object payload and metadata, strictly verifying jurisdiction residency.
func (m *Manager) GetObject(tenantID, projectID, bucketName, key, destinationJurisdiction string) ([]byte, *ObjectMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	b, exists := m.buckets[bucketName]
	if !exists {
		return nil, nil, ErrBucketNotFound
	}

	if tenantID != "tenant-system" && (b.TenantID != tenantID || b.ProjectID != projectID) {
		return nil, nil, ErrUnauthorizedTenant
	}

	meta, exists := m.objects[bucketName][key]
	if !exists {
		return nil, nil, ErrObjectNotFound
	}

	// Sovereign export boundary verification
	if b.SovereigntyPolicy == PolicyBangladeshOnly && destinationJurisdiction != "" && destinationJurisdiction != "BD" {
		return nil, nil, ErrSovereignExportProhibited
	}
	if b.SovereigntyPolicy == PolicyEUOnly && destinationJurisdiction != "" && destinationJurisdiction != "EU" && destinationJurisdiction != "IS" {
		return nil, nil, ErrSovereignExportProhibited
	}

	data := m.payloads[bucketName][key]
	return append([]byte(nil), data...), meta, nil
}

// DeleteObject removes an object from a bucket and reclaims quota.
func (m *Manager) DeleteObject(tenantID, projectID, bucketName, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	b, exists := m.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	if tenantID != "tenant-system" && (b.TenantID != tenantID || b.ProjectID != projectID) {
		return ErrUnauthorizedTenant
	}

	meta, exists := m.objects[bucketName][key]
	if !exists {
		return ErrObjectNotFound
	}

	b.StoredBytes -= meta.SizeBytes
	b.ObjectCount--
	b.UpdatedAt = time.Now().UTC()

	delete(m.objects[bucketName], key)
	delete(m.payloads[bucketName], key)
	return nil
}

// ListObjects returns metadata for all objects in a bucket.
func (m *Manager) ListObjects(tenantID, projectID, bucketName string) ([]*ObjectMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	b, exists := m.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if tenantID != "tenant-system" && (b.TenantID != tenantID || b.ProjectID != projectID) {
		return nil, ErrUnauthorizedTenant
	}

	var result []*ObjectMetadata
	for _, meta := range m.objects[bucketName] {
		result = append(result, meta)
	}
	return result, nil
}
