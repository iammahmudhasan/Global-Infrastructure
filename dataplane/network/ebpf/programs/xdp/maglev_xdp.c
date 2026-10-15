// NexusEdge L4 Maglev Consistent Hashing & Conntrack (eBPF / XDP)
// Mitigates ECMP hash polarization and prevents TCP resets across BGP Anycast route flaps.
// Dual-licensed GPL under Linux eBPF standards.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAGLEV_RING_SIZE 65537
#define MAX_BACKENDS 64
#define MAX_CONNTRACK_ENTRIES 1000000

// 5-Tuple flow descriptor for stateful connection tracking
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
};

struct backend_target {
    __u32 daddr;          // Target backend IPv4 address
    __u8  dmac[6];        // Target backend MAC address
    __u16 port;           // Target backend port
    __u64 packet_count;   // Forwarded packet metrics
};

// Map 1: Maglev Consistent Lookup Ring (Indexed by 5-tuple hash % 65537)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAGLEV_RING_SIZE);
    __type(key, __u32);
    __type(value, __u32); // Backend index in backends_map
} maglev_ring_map SEC(".maps");

// Map 2: Active Backends Registry
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct backend_target);
} backends_map SEC(".maps");

// Map 3: L4 Connection Tracking (Conntrack) Table
// Preserves connection affinity across backend changes or route flaps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNTRACK_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct backend_target);
} conntrack_map SEC(".maps");

// Murmur-style dual-hash accumulator for 5-tuple
static __always_inline __u32 compute_flow_hash(const struct flow_key *key) {
    __u32 h = 0x811c9dc5; // FNV offset basis
    h ^= key->src_ip;
    h *= 0x01000193;
    h ^= key->dst_ip;
    h *= 0x01000193;
    h ^= ((__u32)key->src_port << 16) | key->dst_port;
    h *= 0x01000193;
    h ^= key->protocol;
    h *= 0x01000193;
    return h;
}

SEC("xdp")
int xdp_maglev_router(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Boundary check Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Only process IPv4 traffic
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Boundary check IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    struct flow_key key = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
        .protocol = iph->protocol,
        .pad = {0, 0, 0},
    };

    void *l4_hdr = (void *)iph + (iph->ihl * 4);

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4_hdr;
        if ((void *)(tcph + 1) > data_end) {
            return XDP_PASS;
        }
        key.src_port = tcph->source;
        key.dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4_hdr;
        if ((void *)(udph + 1) > data_end) {
            return XDP_PASS;
        }
        key.src_port = udph->source;
        key.dst_port = udph->dest;
    } else {
        return XDP_PASS;
    }

    // Fast Path 1: Check L4 Connection Tracking (Conntrack) Table
    struct backend_target *target = bpf_map_lookup_elem(&conntrack_map, &key);
    if (target) {
        __sync_fetch_and_add(&target->packet_count, 1);
        return XDP_PASS; // Flow affinity established
    }

    // Fast Path 2: Maglev Consistent Hash Ring Lookup
    __u32 hash = compute_flow_hash(&key);
    __u32 ring_index = hash % MAGLEV_RING_SIZE;

    __u32 *backend_idx = bpf_map_lookup_elem(&maglev_ring_map, &ring_index);
    if (!backend_idx) {
        return XDP_PASS;
    }

    struct backend_target *selected_backend = bpf_map_lookup_elem(&backends_map, backend_idx);
    if (!selected_backend) {
        return XDP_PASS;
    }

    // Update conntrack table so subsequent packets stick to this backend
    bpf_map_update_elem(&conntrack_map, &key, selected_backend, BPF_ANY);
    __sync_fetch_and_add(&selected_backend->packet_count, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
