//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") counter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 4, // icmp,udp,tcp, other
};

static __always_inline int is_countable(struct xdp_md *ctx,u32 *proto) {
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1 > data_end)) {
        return 0;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 0;
    }

    struct iphdr *ip = (void*)(eth+1);

    if ((void *)(ip+1)>data_end) {
        return 0;
    }

    if (ip->protocol == IPPROTO_ICMP || ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_TCP) {
        *proto = (u32)ip->protocol;
    } else {
        *proto = 0;
    }
    return 1;
}


SEC("xdp")
int xdp_function(struct xdp_md *ctx) {
    u32 proto;
    if(!is_countable(ctx,&proto)) {
        goto action;
    } 

    u32 *pkt_count = bpf_map_lookup_elem(&counter,&proto);
    
    // if pkt_count = 0, !0 is 1 so we go inside the if
    if(!pkt_count) {
        u64 init_pkt_count = 1;
        bpf_map_update_elem(&counter,&proto,&init_pkt_count,BPF_ANY);
    } else {
        //This function atomically adds the value of __v to the variable that __p points to. 
        //The result is stored in the address that is specified by __p.
        __sync_fetch_and_add(pkt_count,1);
    }

action:
    return XDP_PASS;
}