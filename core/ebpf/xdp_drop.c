// NexusEdge Kernel-Level L4 DDoS Shield (eBPF / XDP)
// Intercepts and drops volumetric attacks at the network interface card (NIC) driver layer.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Map storing blocked IP addresses in network byte order
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);   // IPv4 address
    __type(value, __u64); // Packet drop counter
} blocked_ips_map SEC(".maps");

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Only process IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 src_ip = iph->saddr;

    // Check if source IP is present in the eBPF blocked map
    __u64 *drop_count = bpf_map_lookup_elem(&blocked_ips_map, &src_ip);
    if (drop_count) {
        __sync_fetch_and_add(drop_count, 1);
        // Instant hardware/driver-level drop: CPU avoids sk_buff allocation
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
