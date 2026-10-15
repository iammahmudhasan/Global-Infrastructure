package packet

import (
	"net"
	"testing"
)

func TestComputeFlowHash_Determinism(t *testing.T) {
	key := FlowKey{
		SrcIP:    0x0A000101, // 10.0.1.1
		DstIP:    0xC6336401, // 198.51.100.1
		SrcPort:  54321,
		DstPort:  443,
		Protocol: IPProtoTCP,
	}

	h1 := ComputeFlowHash(&key)
	h2 := ComputeFlowHash(&key)

	if h1 == 0 {
		t.Fatalf("expected non-zero hash")
	}
	if h1 != h2 {
		t.Fatalf("hash non-deterministic: %d vs %d", h1, h2)
	}

	// Change one byte -> hash must differ
	key2 := key
	key2.SrcPort = 54322
	h3 := ComputeFlowHash(&key2)
	if h1 == h3 {
		t.Fatalf("hash collision on 1-port difference")
	}
}

func TestXDPMaglevRouter_ConntrackAndRingLookup(t *testing.T) {
	router := NewXDPMaglevRouter()

	// Register 3 backends
	_ = router.SetBackend(0, BackendTarget{DAddr: 0xAC1E0003, Port: 8080}) // 172.30.0.3
	_ = router.SetBackend(1, BackendTarget{DAddr: 0xAC1E0004, Port: 8080}) // 172.30.0.4
	_ = router.SetBackend(2, BackendTarget{DAddr: 0xAC1E0005, Port: 8080}) // 172.30.0.5

	// Populate ring round-robin
	var ring [MaglevRingSize]uint32
	for i := 0; i < MaglevRingSize; i++ {
		ring[i] = uint32(i % 3)
	}
	router.SetRing(ring)

	flow := FlowKey{
		SrcIP:    0x0A000105,
		DstIP:    0x6790B401,
		SrcPort:  40000,
		DstPort:  443,
		Protocol: IPProtoTCP,
	}

	// First packet: Fast Path 2 (Maglev Ring lookup + Conntrack store)
	act1, b1 := router.ProcessFlow(&flow)
	if act1 != XDPPass || b1 == nil {
		t.Fatalf("expected XDPPass and non-nil backend")
	}
	if router.MaglevHits != 1 || router.ConntrackHits != 0 {
		t.Fatalf("expected 1 Maglev hit and 0 Conntrack hits, got %d and %d", router.MaglevHits, router.ConntrackHits)
	}

	// Second packet: Fast Path 1 (Conntrack cache hit)
	act2, b2 := router.ProcessFlow(&flow)
	if act2 != XDPPass || b2 != b1 {
		t.Fatalf("flow affinity broken: backend changed from %v to %v", b1, b2)
	}
	if router.MaglevHits != 1 || router.ConntrackHits != 1 {
		t.Fatalf("expected 1 Maglev hit and 1 Conntrack hit, got %d and %d", router.MaglevHits, router.ConntrackHits)
	}

	if b1.PacketCount != 2 {
		t.Fatalf("expected backend packet count 2, got: %d", b1.PacketCount)
	}
}

func TestXDPMaglevRouter_RawPacketBoundaryCheck(t *testing.T) {
	router := NewXDPMaglevRouter()
	_ = router.SetBackend(0, BackendTarget{DAddr: 0xAC1E0003, Port: 8080})
	var ring [MaglevRingSize]uint32
	router.SetRing(ring)

	// 1. Truncated packet (< 14 bytes) -> XDPPass, nil
	shortPkt := []byte{0x01, 0x02, 0x03}
	act, b := router.ProcessRawPacket(shortPkt)
	if act != XDPPass || b != nil {
		t.Fatalf("expected XDPPass and nil backend for truncated packet")
	}

	// 2. Non-IPv4 packet (ARP: 0x0806) -> XDPPass, nil
	arpPkt := make([]byte, 28)
	arpPkt[12] = 0x08
	arpPkt[13] = 0x06
	act, b = router.ProcessRawPacket(arpPkt)
	if act != XDPPass || b != nil {
		t.Fatalf("expected XDPPass and nil backend for non-IPv4 packet")
	}

	// 3. Fully compliant raw IPv4 TCP packet
	srcIP := net.ParseIP("10.10.1.1")
	dstIP := net.ParseIP("103.144.180.1")
	validPkt := BuildSyntheticPacket(srcIP, dstIP, 54321, 443, IPProtoTCP, []byte("GET / HTTP/1.1\r\n"))

	act, b = router.ProcessRawPacket(validPkt)
	if act != XDPPass || b == nil {
		t.Fatalf("expected XDPPass and valid backend for synthetic raw packet")
	}
	if b.DAddr != 0xAC1E0003 {
		t.Fatalf("expected backend DAddr 0xAC1E0003, got: 0x%X", b.DAddr)
	}
}
