//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";
#define MAX_MAP_ENTRIES 16 

/*
struct bpf_map_def SEC("maps") counter = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};
*/


struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,10); // max interfaces number
    __type(key,__u32); // __u32 ingress_ifindex; defined in xdp_md struct
    __type(value,__u64); // counter

} if_counter_map SEC(".maps");

// Define a BPF map named 'counter' of type BPF_MAP_TYPE_ARRAY with maximum 1 entry.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); 
    __type(value, __u64);
} counter SEC(".maps");

// Function to check if the packet is IPv4.
static __always_inline int is_ipv4(struct xdp_md *ctx) {
    // Get pointers to the start and end of the packet data.
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
        } else {
        // If the value exists, increment it atomically.
        __sync_fetch_and_add(valp, 1);
        } 

        u32 ifindex = ctx->ingress_ifindex;
        u64 *ifcounter = bpf_map_lookup_elem(&if_counter_map,&ifindex);
        if(!ifcounter) {
            u64 init_ifcounter = 1;
            bpf_map_update_elem(&if_counter_map,&ifindex,&init_ifcounter,BPF_ANY);
        } else {
            __sync_fetch_and_add(ifcounter,1);
        }        
    } 

    // Return XDP_PASS to indicate that the packet should be passed through.
    return XDP_PASS;
}




