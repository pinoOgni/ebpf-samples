//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";
#define MAX_MAP_ENTRIES 16 

volatile __s64 global_counter = 0;  //.bss

// BTF Style Maps: More info here https://docs.ebpf.io/linux/concepts/maps/#btf-style-maps
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); 
    __type(value, __u64);
} counter SEC(".maps");

// Legacy Maps. More info here https://docs.ebpf.io/linux/concepts/maps/#legacy-maps
// struct bpf_map_def SEC("maps") counter = {
//     .type = BPF_MAP_TYPE_ARRAY,
//     .key_size = sizeof(__u32),
//     .value_size = sizeof(__u64),
//     .max_entries = 1
// } ;

// Function to check if the packet is IPv4.
__always_inline int is_ipv4(struct xdp_md *ctx) {
    // Get pointers to the start and end of the packet data.
    void *data_end = (void*)(long)ctx->data_end; 
    void *data = (void*)(long)ctx->data;

    // Parse the Ethernet header.
    struct ethhdr *eth = data;
    // Check if Ethernet header extends beyond packet data end.
    if ((void *)(eth + 1) > data_end) {
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
    // Check if the packet is IPv4.
    if (is_ipv4(ctx)) {
        // If the packet is IPv4, update the counter.
        u32 key = 0;
        u64 initval = 1, *valp;
        // Lookup the value in the 'counter' map.
        valp = bpf_map_lookup_elem(&counter, &key);
        if (!valp) {
            // If the value does not exist in the map, update it with the initial value.
            bpf_map_update_elem(&counter, &key, &initval, BPF_ANY);
            return 0;
        }
        // If the value exists, increment it atomically.
        // The controlplane is reading the map and prints it.
        __sync_fetch_and_add(valp, 1);

        // Increment also the global counter and print it (just to show the bpf_printk in bpftool output).
        __sync_fetch_and_add(&global_counter,1);
        bpf_printk("global_counter value %u\n",global_counter);
    } 

    // Return XDP_PASS to indicate that the packet should be passed through.
    return XDP_PASS;
}

