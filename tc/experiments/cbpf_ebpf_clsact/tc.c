//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

char __license[] SEC("license") = "GPL";

// Define a map for ingress counter packets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} counter_map SEC(".maps");


SEC("tc_ingress")
int tc_ingress_f(struct __sk_buff *skb)
{
        
    __u32 *counter;
    __u32 mapKey = 0;
    // Lookup the appropriate map based on the passed map pointer
    counter = bpf_map_lookup_elem(&counter_map, &mapKey);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    return TC_ACT_OK; // Allow the packet
}

