//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";


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
        // hardcoded
        __u32 if_index = 8; // interface index to redirect to

        return bpf_redirect(if_index,0);
        // Try this line and see what happens
        // bpf_redirect(if_index,0); 
    } 

    // Return XDP_PASS to indicate that the packet should be passed through.
    return XDP_PASS;
}

