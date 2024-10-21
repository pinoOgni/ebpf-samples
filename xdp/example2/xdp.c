//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";


struct bpf_map_def SEC("maps") counter = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,
};

static __always_inline int is_ipv6(struct xdp_md *ctx) {
        void *data_end = (void*)(long)ctx->data_end;
        void *data = (void*)(long)ctx->data;

        struct ethhdr *eth = data;
        if ((void *)(eth +1 > data_end)) {
            return 0;
        }
        if (eth->h_proto != bpf_htons(ETH_P_IP6)) {
            return 0;
        }
        struct ipv6hdr *ip6 = (void *)(eth + 1);

        if ((void *)(ip6 + 1) > data_end) {
            return 0;
        } 
        return 1;
}


SEC("xdp") 
int xdp_function(struct xdp_md *ctx) {
    if(is_ipv6(ctx)) {
       u32 key = 0;
       u32 initval = 1, *valp;

       valp = bpf_map_lookup_elem(&counter,&key);
       if (!valp) {
        bpf_map_update_elem(&counter,&key,&initval,BPF_ANY);
        return 0;
       }
       __sync_fetch_and_add(valp,1);
    }
    return XDP_PASS;
}
