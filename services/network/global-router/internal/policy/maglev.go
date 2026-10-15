package policy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"sync"
	"time"
)

var (
	ErrNoBackendsAvailable = errors.New("no healthy backends available for Maglev consistent hashing")
	ErrInvalidTableSize    = errors.New("maglev table size must be a prime number")
)

// DefaultMaglevTableSize is a prime number ensuring optimal distribution without prime collisions.
// Standard Maglev size used by Google Maglev and Meta Katran.
const DefaultMaglevTableSize = 65537

// FiveTuple identifies an L4 TCP/UDP network flow.
type FiveTuple struct {
	SrcIP    net.IP
	SrcPort  uint16
	DstIP    net.IP
	DstPort  uint16
	Protocol uint8 // 6 for TCP, 17 for UDP
}

func (f FiveTuple) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d (proto: %d)", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol)
}

// BackendNode represents an edge gateway or proxy server instance in a PoP.
type BackendNode struct {
	ID     string
	IP     net.IP
	Port   uint16
	Weight int
}

// ConntrackEntry tracks an active connection to ensure flow affinity across lookup changes.
type ConntrackEntry struct {
	Backend   *BackendNode
	ExpiresAt time.Time
}

// ConntrackTable maintains stateful flow tracking at L4 to prevent TCP resets.
type ConntrackTable struct {
	mu      sync.RWMutex
	entries map[string]ConntrackEntry
	ttl     time.Duration
}

func NewConntrackTable(ttl time.Duration) *ConntrackTable {
	if ttl <= 0 {
		ttl = 120 * time.Second
	}
	return &ConntrackTable{
		entries: make(map[string]ConntrackEntry),
		ttl:     ttl,
	}
}

func (ct *ConntrackTable) flowKey(f FiveTuple) string {
	return fmt.Sprintf("%s|%d|%s|%d|%d", f.SrcIP.String(), f.SrcPort, f.DstIP.String(), f.DstPort, f.Protocol)
}

func (ct *ConntrackTable) Lookup(f FiveTuple, now time.Time) (*BackendNode, bool) {
	key := ct.flowKey(f)
	ct.mu.RLock()
	entry, exists := ct.entries[key]
	ct.mu.RUnlock()

	if !exists {
		return nil, false
	}

	if now.After(entry.ExpiresAt) {
		ct.mu.Lock()
		delete(ct.entries, key)
		ct.mu.Unlock()
		return nil, false
	}

	return entry.Backend, true
}

func (ct *ConntrackTable) Track(f FiveTuple, backend *BackendNode, now time.Time) {
	key := ct.flowKey(f)
	ct.mu.Lock()
	ct.entries[key] = ConntrackEntry{
		Backend:   backend,
		ExpiresAt: now.Add(ct.ttl),
	}
	ct.mu.Unlock()
}

func (ct *ConntrackTable) PurgeExpired(now time.Time) int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	purged := 0
	for k, v := range ct.entries {
		if now.After(v.ExpiresAt) {
			delete(ct.entries, k)
			purged++
		}
	}
	return purged
}

// MaglevConsistentHash implements the Google Maglev consistent hashing algorithm.
type MaglevConsistentHash struct {
	mu          sync.RWMutex
	tableSize   int
	backends    []*BackendNode
	lookupTable []int // Indices into backends slice
	conntrack   *ConntrackTable
}

// NewMaglevConsistentHash initializes a Maglev load balancing ring.
func NewMaglevConsistentHash(tableSize int, conntrackTTL time.Duration) (*MaglevConsistentHash, error) {
	if tableSize <= 0 {
		tableSize = DefaultMaglevTableSize
	}
	if !isPrime(tableSize) {
		return nil, ErrInvalidTableSize
	}

	return &MaglevConsistentHash{
		tableSize: tableSize,
		backends:  make([]*BackendNode, 0),
		conntrack: NewConntrackTable(conntrackTTL),
	}, nil
}

// SetBackends atomically rebuilds the Maglev lookup table with the given backends.
func (m *MaglevConsistentHash) SetBackends(backends []*BackendNode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(backends) == 0 {
		m.backends = nil
		m.lookupTable = nil
		return ErrNoBackendsAvailable
	}

	n := len(backends)
	mSize := m.tableSize

	// Step 1: Generate permutation for each backend
	// offset = h1(backend) % M
	// skip = (h2(backend) % (M - 1)) + 1
	// permutation[j] = (offset + j * skip) % M
	permutations := make([][]int, n)
	for i, b := range backends {
		h1 := hashFNV1a(b.ID)
		h2 := hashDJB2(b.ID)

		offset := int(h1 % uint64(mSize))
		skip := int((h2 % uint64(mSize-1)) + 1)

		perm := make([]int, mSize)
		for j := 0; j < mSize; j++ {
			perm[j] = (offset + j*skip) % mSize
		}
		permutations[i] = perm
	}

	// Step 2: Populate lookup table round-robin
	lookup := make([]int, mSize)
	for i := range lookup {
		lookup[i] = -1
	}

	nextIdx := make([]int, n)
	filledSlots := 0

	for filledSlots < mSize {
		for i := 0; i < n; i++ {
			c := nextIdx[i]
			for c < mSize && lookup[permutations[i][c]] != -1 {
				c++
			}
			if c < mSize {
				lookup[permutations[i][c]] = i
				nextIdx[i] = c + 1
				filledSlots++
				if filledSlots == mSize {
					break
				}
			}
		}
	}

	m.backends = backends
	m.lookupTable = lookup
	return nil
}

// Dispatch routes a 5-tuple network flow consistently to a backend node.
func (m *MaglevConsistentHash) Dispatch(f FiveTuple, now time.Time) (*BackendNode, error) {
	// Fast-path: Check L4 Connection Tracking (Conntrack) Table
	if backend, hit := m.conntrack.Lookup(f, now); hit {
		return backend, nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.backends) == 0 || len(m.lookupTable) == 0 {
		return nil, ErrNoBackendsAvailable
	}

	// 5-tuple flow hash
	flowHash := hash5Tuple(f)
	slot := int(flowHash % uint64(m.tableSize))
	backendIdx := m.lookupTable[slot]
	backend := m.backends[backendIdx]

	// Track connection state
	m.conntrack.Track(f, backend, now)

	return backend, nil
}

// Conntrack returns the underlying connection tracking table.
func (m *MaglevConsistentHash) Conntrack() *ConntrackTable {
	return m.conntrack
}

// Helper: FNV-1a 64-bit hash
func hashFNV1a(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// Helper: DJB2 64-bit hash
func hashDJB2(s string) uint64 {
	var hash uint64 = 5381
	for i := 0; i < len(s); i++ {
		hash = ((hash << 5) + hash) + uint64(s[i])
	}
	return hash
}

// Helper: 5-Tuple Murmur-style hash
func hash5Tuple(f FiveTuple) uint64 {
	var buf [13]byte
	if len(f.SrcIP) >= 4 && len(f.DstIP) >= 4 {
		src4 := f.SrcIP.To4()
		dst4 := f.DstIP.To4()
		if src4 != nil && dst4 != nil {
			copy(buf[0:4], src4)
			copy(buf[4:8], dst4)
		} else {
			copy(buf[0:4], f.SrcIP[:4])
			copy(buf[4:8], f.DstIP[:4])
		}
	}
	binary.BigEndian.PutUint16(buf[8:10], f.SrcPort)
	binary.BigEndian.PutUint16(buf[10:12], f.DstPort)
	buf[12] = f.Protocol

	h := fnv.New64a()
	_, _ = h.Write(buf[:])
	return h.Sum64()
}

// isPrime validates primality for Maglev table sizing.
func isPrime(n int) bool {
	if n <= 1 {
		return false
	}
	if n <= 3 {
		return true
	}
	if n%2 == 0 || n%3 == 0 {
		return false
	}
	for i := 5; i*i <= n; i += 6 {
		if n%i == 0 || n%(i+2) == 0 {
			return false
		}
	}
	return true
}
