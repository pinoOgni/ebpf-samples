#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>

// Define a map for ingress byte counts
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ingress_map SEC(".maps");

// Define a map for egress byte counts
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} egress_map SEC(".maps");

// Modified account_data function to accept a map variable
static __inline int account_data(struct __sk_buff *skb, void *map_ptr)
{
    __u32 *bytes;
     __u32 mapKey = 0;
    // Lookup the appropriate map based on the passed map pointer
    bytes = bpf_map_lookup_elem(map_ptr, &mapKey);
    if (bytes)
        __sync_fetch_and_add(bytes, skb->len);

    return TC_ACT_OK;
}

// Ingress program (for BPF_PROG_TYPE_SCHED_CLS)
SEC("ingress")
int tc_ingress(struct __sk_buff *skb)
{
    return account_data(skb, &ingress_map);
}

// Egress program (for BPF_PROG_TYPE_SCHED_CLS)
SEC("egress")
int tc_egress(struct __sk_buff *skb)
{
    return account_data(skb, &egress_map);
}

char __license[] SEC("license") = "GPL";
