package packet

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

const (
	MaglevRingSize      = 65537
	MaxBackends         = 64
	MaxConntrackEntries = 1000000

	EthProtoIPv4 = 0x0800
	IPProtoTCP   = 6
	IPProtoUDP   = 17

	EthHdrLen  = 14
	IPv4MinLen = 20
	TCPMinLen  = 20
	UDPMinLen  = 8
)

type XDPAction int

const (
	XDPAborted  XDPAction = 0
	XDPDrop     XDPAction = 1
	XDPPass     XDPAction = 2
	XDPTx       XDPAction = 3
	XDPRedirect XDPAction = 4
)

// FlowKey matches struct flow_key in dataplane/network/ebpf/programs/xdp/maglev_xdp.c
type FlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Pad      [3]byte
}

// BackendTarget matches struct backend_target in maglev_xdp.c
type BackendTarget struct {
	DAddr       uint32
	DMAC        [6]byte
	Port        uint16
	PacketCount uint64
}

// ComputeFlowHash computes the FNV-1a Murmur-style 32-bit hash identical to compute_flow_hash() in maglev_xdp.c
func ComputeFlowHash(key *FlowKey) uint32 {
	h := uint32(0x811c9dc5)
	h ^= key.SrcIP
	h *= 0x01000193
	h ^= key.DstIP
	h *= 0x01000193
	h ^= (uint32(key.SrcPort) << 16) | uint32(key.DstPort)
	h *= 0x01000193
	h ^= uint32(key.Protocol)
	h *= 0x01000193
	return h
}

// XDPMaglevRouter implements userspace kernel-parity simulation of maglev_xdp.c
type XDPMaglevRouter struct {
	ring        [MaglevRingSize]uint32
	backends    [MaxBackends]BackendTarget
	numBackends int
	conntrack   sync.Map // FlowKey -> *BackendTarget

	TotalPackets   uint64
	ConntrackHits  uint64
	MaglevHits     uint64
	DroppedPackets uint64
}

// NewXDPMaglevRouter initializes the simulated XDP router.
func NewXDPMaglevRouter() *XDPMaglevRouter {
	return &XDPMaglevRouter{
		numBackends: 0,
	}
}

// SetBackend registers a target backend node.
func (r *XDPMaglevRouter) SetBackend(idx uint32, target BackendTarget) error {
	if idx >= MaxBackends {
		return errors.New("backend index exceeds MaxBackends")
	}
	r.backends[idx] = target
	if int(idx)+1 > r.numBackends {
		r.numBackends = int(idx) + 1
	}
	return nil
}

// SetRing sets the precomputed Maglev lookup table.
func (r *XDPMaglevRouter) SetRing(ring [MaglevRingSize]uint32) {
	r.ring = ring
}

// ProcessFlow processes a 5-tuple flow through Fast Path 1 (Conntrack) and Fast Path 2 (Maglev Ring).
func (r *XDPMaglevRouter) ProcessFlow(key *FlowKey) (XDPAction, *BackendTarget) {
	atomic.AddUint64(&r.TotalPackets, 1)

	// Fast Path 1: Check L4 Connection Tracking (Conntrack) Table
	if val, ok := r.conntrack.Load(*key); ok {
		target := val.(*BackendTarget)
		atomic.AddUint64(&target.PacketCount, 1)
		atomic.AddUint64(&r.ConntrackHits, 1)
		return XDPPass, target
	}

	// Fast Path 2: Maglev Consistent Hash Ring Lookup
	hash := ComputeFlowHash(key)
	ringIndex := hash % MaglevRingSize
	backendIdx := r.ring[ringIndex]

	if backendIdx >= uint32(r.numBackends) {
		atomic.AddUint64(&r.DroppedPackets, 1)
		return XDPPass, nil
	}

	selectedBackend := &r.backends[backendIdx]
	r.conntrack.Store(*key, selectedBackend)
	atomic.AddUint64(&selectedBackend.PacketCount, 1)
	atomic.AddUint64(&r.MaglevHits, 1)

	return XDPPass, selectedBackend
}

// ProcessRawPacket parses raw Ethernet + IPv4 + TCP/UDP headers and evaluates XDP policy.
func (r *XDPMaglevRouter) ProcessRawPacket(data []byte) (XDPAction, *BackendTarget) {
	dataLen := len(data)

	// Boundary check Ethernet header
	if dataLen < EthHdrLen {
		return XDPPass, nil
	}

	ethProto := binary.BigEndian.Uint16(data[12:14])
	if ethProto != EthProtoIPv4 {
		return XDPPass, nil
	}

	// Boundary check IPv4 header
	if dataLen < EthHdrLen+IPv4MinLen {
		return XDPPass, nil
	}

	ipData := data[EthHdrLen:]
	ihl := int(ipData[0]&0x0F) * 4
	if ihl < IPv4MinLen || dataLen < EthHdrLen+ihl {
		return XDPPass, nil
	}

	protocol := ipData[9]
	srcIP := binary.BigEndian.Uint32(ipData[12:16])
	dstIP := binary.BigEndian.Uint32(ipData[16:20])

	l4Offset := EthHdrLen + ihl
	var srcPort, dstPort uint16

	if protocol == IPProtoTCP {
		if dataLen < l4Offset+TCPMinLen {
			return XDPPass, nil
		}
		srcPort = binary.BigEndian.Uint16(data[l4Offset : l4Offset+2])
		dstPort = binary.BigEndian.Uint16(data[l4Offset+2 : l4Offset+4])
	} else if protocol == IPProtoUDP {
		if dataLen < l4Offset+UDPMinLen {
			return XDPPass, nil
		}
		srcPort = binary.BigEndian.Uint16(data[l4Offset : l4Offset+2])
		dstPort = binary.BigEndian.Uint16(data[l4Offset+2 : l4Offset+4])
	} else {
		return XDPPass, nil
	}

	key := FlowKey{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	return r.ProcessFlow(&key)
}

// BuildSyntheticPacket generates a compliant raw Ethernet + IPv4 + TCP/UDP test packet.
func BuildSyntheticPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8, payload []byte) []byte {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		src4 = net.IPv4(192, 0, 2, 1).To4()
		dst4 = net.IPv4(198, 51, 100, 1).To4()
	}

	ipTotalLen := uint16(IPv4MinLen + TCPMinLen + len(payload))
	totalLen := EthHdrLen + int(ipTotalLen)
	pkt := make([]byte, totalLen)

	// Ethernet Header (14 bytes)
	copy(pkt[0:6], []byte{0x02, 0x00, 0x5E, 0x00, 0x00, 0x01})  // Dst MAC
	copy(pkt[6:12], []byte{0x02, 0x00, 0x5E, 0x00, 0x00, 0x02}) // Src MAC
	binary.BigEndian.PutUint16(pkt[12:14], EthProtoIPv4)

	// IPv4 Header (20 bytes)
	ipOff := EthHdrLen
	pkt[ipOff] = 0x45 // Version 4, IHL 5 (20 bytes)
	pkt[ipOff+1] = 0x00
	binary.BigEndian.PutUint16(pkt[ipOff+2:ipOff+4], ipTotalLen)
	binary.BigEndian.PutUint16(pkt[ipOff+4:ipOff+6], 0x1234)
	binary.BigEndian.PutUint16(pkt[ipOff+6:ipOff+8], 0x4000) // Don't Fragment
	pkt[ipOff+8] = 64                                        // TTL
	pkt[ipOff+9] = proto                                     // Protocol
	copy(pkt[ipOff+12:ipOff+16], src4)
	copy(pkt[ipOff+16:ipOff+20], dst4)

	// L4 Header
	l4Off := ipOff + IPv4MinLen
	binary.BigEndian.PutUint16(pkt[l4Off:l4Off+2], srcPort)
	binary.BigEndian.PutUint16(pkt[l4Off+2:l4Off+4], dstPort)
	if proto == IPProtoTCP {
		pkt[l4Off+12] = 0x50 // Data offset 5 (20 bytes)
		pkt[l4Off+13] = 0x02 // SYN flag
		binary.BigEndian.PutUint16(pkt[l4Off+14:l4Off+16], 65535)
	}

	if len(payload) > 0 {
		copy(pkt[l4Off+TCPMinLen:], payload)
	}

	return pkt
}
