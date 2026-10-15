package packet

import (
	"math/rand"
	"net"
	"sync/atomic"
	"testing"
)

func initRouterWithBackends() *XDPMaglevRouter {
	router := NewXDPMaglevRouter()
	for i := 0; i < 8; i++ {
		_ = router.SetBackend(uint32(i), BackendTarget{
			DAddr: 0xAC1E0000 + uint32(i),
			Port:  8080,
		})
	}

	var ring [MaglevRingSize]uint32
	for i := 0; i < MaglevRingSize; i++ {
		ring[i] = uint32(i % 8)
	}
	router.SetRing(ring)
	return router
}

// BenchmarkXDP_ConntrackHit measures Fast Path 1 (L4 connection tracking cache hit speed).
func BenchmarkXDP_ConntrackHit(b *testing.B) {
	router := initRouterWithBackends()

	flow := FlowKey{
		SrcIP:    0x0A000101,
		DstIP:    0x6790B401,
		SrcPort:  50000,
		DstPort:  443,
		Protocol: IPProtoTCP,
	}

	// Warm up conntrack entry
	router.ProcessFlow(&flow)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		router.ProcessFlow(&flow)
	}

	// Calculate and report Mpps (Million packets per second)
	elapsedSec := b.Elapsed().Seconds()
	if elapsedSec > 0 {
		mpps := (float64(b.N) / elapsedSec) / 1_000_000.0
		b.ReportMetric(mpps, "Mpps")
	}
}

// BenchmarkXDP_MaglevMiss_NewFlow measures Fast Path 2 (New flow dual-hash and ring lookup).
func BenchmarkXDP_MaglevMiss_NewFlow(b *testing.B) {
	router := initRouterWithBackends()

	// Pre-generate unique flows
	flows := make([]FlowKey, 10000)
	rng := rand.New(rand.NewSource(42))
	for i := range flows {
		flows[i] = FlowKey{
			SrcIP:    rng.Uint32(),
			DstIP:    0x6790B401,
			SrcPort:  uint16(rng.Intn(65535)),
			DstPort:  443,
			Protocol: IPProtoTCP,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		flow := &flows[i%len(flows)]
		router.ProcessFlow(flow)
	}

	elapsedSec := b.Elapsed().Seconds()
	if elapsedSec > 0 {
		mpps := (float64(b.N) / elapsedSec) / 1_000_000.0
		b.ReportMetric(mpps, "Mpps")
	}
}

// BenchmarkXDP_RawPacketDissection measures full zero-copy packet boundary checking and header extraction.
func BenchmarkXDP_RawPacketDissection(b *testing.B) {
	router := initRouterWithBackends()

	rawPkt := BuildSyntheticPacket(
		net.ParseIP("10.10.1.1"),
		net.ParseIP("103.144.180.1"),
		54321,
		443,
		IPProtoTCP,
		[]byte("GET /healthz HTTP/1.1\r\n\r\n"),
	)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		router.ProcessRawPacket(rawPkt)
	}

	elapsedSec := b.Elapsed().Seconds()
	if elapsedSec > 0 {
		mpps := (float64(b.N) / elapsedSec) / 1_000_000.0
		b.ReportMetric(mpps, "Mpps")
	}
}

// BenchmarkXDP_MultiCore_Parallel measures multi-threaded saturation simulating multi-queue RSS NICs.
func BenchmarkXDP_MultiCore_Parallel(b *testing.B) {
	router := initRouterWithBackends()

	var counter uint64

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		flow := FlowKey{
			SrcIP:    0x0A000101 + uint32(atomic.AddUint64(&counter, 1)%1000),
			DstIP:    0x6790B401,
			SrcPort:  50000,
			DstPort:  443,
			Protocol: IPProtoTCP,
		}
		for pb.Next() {
			router.ProcessFlow(&flow)
		}
	})

	elapsedSec := b.Elapsed().Seconds()
	if elapsedSec > 0 {
		mpps := (float64(b.N) / elapsedSec) / 1_000_000.0
		b.ReportMetric(mpps, "Mpps")
	}
}
