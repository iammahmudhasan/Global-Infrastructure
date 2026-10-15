package policy

import (
	"fmt"
	"math"
	"net"
	"testing"
	"time"
)

func TestMaglevInitializationAndPrimeValidation(t *testing.T) {
	// 1. Non-prime table size rejected
	_, err := NewMaglevConsistentHash(100, 30*time.Second)
	if err == nil {
		t.Fatal("expected error for non-prime table size 100, got nil")
	}

	// 2. Prime table size accepted (e.g. 257 or Default 65537)
	maglev, err := NewMaglevConsistentHash(257, 30*time.Second)
	if err != nil {
		t.Fatalf("expected success for prime table size 257, got: %v", err)
	}
	if maglev.tableSize != 257 {
		t.Fatalf("expected table size 257, got: %d", maglev.tableSize)
	}

	// 3. Default prime table size (65537)
	maglevDefault, err := NewMaglevConsistentHash(0, 30*time.Second)
	if err != nil {
		t.Fatalf("expected success for default table size, got: %v", err)
	}
	if maglevDefault.tableSize != DefaultMaglevTableSize {
		t.Fatalf("expected default table size %d, got: %d", DefaultMaglevTableSize, maglevDefault.tableSize)
	}
}

func TestMaglevUniformDistribution(t *testing.T) {
	// Test on prime size 65537 with 5 backends
	maglev, err := NewMaglevConsistentHash(DefaultMaglevTableSize, 60*time.Second)
	if err != nil {
		t.Fatalf("failed to create maglev: %v", err)
	}

	backends := []*BackendNode{
		{ID: "node-sin-01", IP: net.ParseIP("10.0.1.1"), Port: 8080},
		{ID: "node-sin-02", IP: net.ParseIP("10.0.1.2"), Port: 8080},
		{ID: "node-sin-03", IP: net.ParseIP("10.0.1.3"), Port: 8080},
		{ID: "node-sin-04", IP: net.ParseIP("10.0.1.4"), Port: 8080},
		{ID: "node-sin-05", IP: net.ParseIP("10.0.1.5"), Port: 8080},
	}

	err = maglev.SetBackends(backends)
	if err != nil {
		t.Fatalf("SetBackends failed: %v", err)
	}

	// Verify that each backend gets roughly M / N slots
	slotCounts := make(map[int]int)
	for _, backendIdx := range maglev.lookupTable {
		slotCounts[backendIdx]++
	}

	expectedPerBackend := float64(DefaultMaglevTableSize) / float64(len(backends))
	tolerance := expectedPerBackend * 0.05 // Within 5% variance

	for i := 0; i < len(backends); i++ {
		count := slotCounts[i]
		diff := math.Abs(float64(count) - expectedPerBackend)
		if diff > tolerance {
			t.Errorf("Backend %d count %d deviates too much from expected %f (tolerance %f)",
				i, count, expectedPerBackend, tolerance)
		}
	}
}

func TestMaglevConsistentAffinityAcrossRebuild(t *testing.T) {
	tableSize := 65537
	maglev, err := NewMaglevConsistentHash(tableSize, 120*time.Second)
	if err != nil {
		t.Fatalf("failed to create maglev: %v", err)
	}

	initialBackends := []*BackendNode{
		{ID: "gw-pop-01", IP: net.ParseIP("10.0.1.10"), Port: 8080},
		{ID: "gw-pop-02", IP: net.ParseIP("10.0.1.11"), Port: 8080},
		{ID: "gw-pop-03", IP: net.ParseIP("10.0.1.12"), Port: 8080},
		{ID: "gw-pop-04", IP: net.ParseIP("10.0.1.13"), Port: 8080},
	}

	err = maglev.SetBackends(initialBackends)
	if err != nil {
		t.Fatalf("SetBackends failed: %v", err)
	}

	now := time.Now()
	numFlows := 1000
	initialAssignments := make(map[string]string)

	for i := 0; i < numFlows; i++ {
		flow := FiveTuple{
			SrcIP:    net.ParseIP(fmt.Sprintf("192.168.1.%d", i%254+1)),
			SrcPort:  uint16(10000 + i),
			DstIP:    net.ParseIP("80.225.241.129"),
			DstPort:  443,
			Protocol: 6, // TCP
		}
		node, err := maglev.Dispatch(flow, now)
		if err != nil {
			t.Fatalf("Dispatch failed: %v", err)
		}
		initialAssignments[flow.String()] = node.ID
	}

	// Now add a 5th backend (scale-out)
	expandedBackends := append(initialBackends, &BackendNode{
		ID:   "gw-pop-05",
		IP:   net.ParseIP("10.0.1.14"),
		Port: 8080,
	})

	err = maglev.SetBackends(expandedBackends)
	if err != nil {
		t.Fatalf("SetBackends expanded failed: %v", err)
	}

	// Active flows must stick to their original node due to Conntrack
	conntrackPreservedCount := 0
	for i := 0; i < numFlows; i++ {
		flow := FiveTuple{
			SrcIP:    net.ParseIP(fmt.Sprintf("192.168.1.%d", i%254+1)),
			SrcPort:  uint16(10000 + i),
			DstIP:    net.ParseIP("80.225.241.129"),
			DstPort:  443,
			Protocol: 6,
		}
		node, err := maglev.Dispatch(flow, now.Add(5*time.Second))
		if err != nil {
			t.Fatalf("Dispatch failed: %v", err)
		}
		if node.ID == initialAssignments[flow.String()] {
			conntrackPreservedCount++
		}
	}

	// 100% of ongoing connections must be preserved across node scale-out via Conntrack!
	if conntrackPreservedCount != numFlows {
		t.Fatalf("expected 100%% of active flows preserved by conntrack, got %d / %d",
			conntrackPreservedCount, numFlows)
	}
}

func TestConntrackPurgeExpired(t *testing.T) {
	ct := NewConntrackTable(10 * time.Second)
	now := time.Now()

	node := &BackendNode{ID: "node-01"}
	flow1 := FiveTuple{SrcPort: 1001, Protocol: 6}
	flow2 := FiveTuple{SrcPort: 1002, Protocol: 6}

	ct.Track(flow1, node, now)
	ct.Track(flow2, node, now)

	// Both active
	if _, hit := ct.Lookup(flow1, now.Add(5*time.Second)); !hit {
		t.Fatal("expected flow1 to be active")
	}

	// Advance past TTL (15s > 10s)
	nowExpired := now.Add(15 * time.Second)
	if _, hit := ct.Lookup(flow1, nowExpired); hit {
		t.Fatal("expected flow1 to have expired")
	}

	purged := ct.PurgeExpired(nowExpired)
	if purged < 1 {
		t.Fatalf("expected at least 1 entry purged, got %d", purged)
	}
}
