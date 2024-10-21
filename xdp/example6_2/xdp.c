//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") ifindex_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,  // Only one element in the array
};

// Function to check if the packet is IPv4.
static __always_inline int is_ipv4(struct xdp_md *ctx) {
    void *data_end = (void*)(long)ctx->data_end; 
    void *data = (void*)(long)ctx->data;

    // Parse the Ethernet header.
    struct ethhdr *eth = data;
    // Check if Ethernet header extends beyond packet data end.
    if ((void *)(eth + 1 > data_end)) {
        return 0;
    }
    // Check if the protocol in the Ethernet header is IPv4.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // The protocol is not IPv4, so we can't parse an IPv4 source address.
        return 0;
    }
    // Parse the IP header.
    struct iphdr *ip = (void *)(eth + 1);
    // Check if IP header extends beyond packet data end.
    if ((void *)(ip + 1) > data_end) {
        return 0;
    }
    // If we are here it means that the packet is not malformed and is an IPv4 packet.
    return 1;
}

SEC("xdp")
int xdp_func(struct xdp_md *ctx) {
    if (is_ipv4(ctx)) {
        u32 key = 0;
        u32 *if_index; // interface index to redirect to
        if_index = bpf_map_lookup_elem(&ifindex_map, &key);
        if (!if_index) {
            // It should not be possible to be here because it means
            // that the map was not populated from the controlplane 
            // before attaching the program and the program must exit
            // https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/implementation/xdp_actions.html#xdp-aborted
            return XDP_ABORTED;
        }
        return bpf_redirect(*if_index,0);
    } 

    // Return XDP_PASS to indicate that the packet should be passed through.
    return XDP_PASS;
}

