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

// Define a map for ingress dropped packets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} dropped_map SEC(".maps");

static __always_inline int is_ipv4_icmp(struct __sk_buff *skb) {
    // Get pointers to the start and end of the packet data.
    void *data_end = (void*)(long)skb->data_end; 
    void *data = (void*)(long)skb->data;

    // Check if there's enough data for both Ethernet and IP headers.
    // In one shot.
    struct ethhdr *eth = data;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    
    if ((void *)(ip + 1) > data_end) {
        return 0; // Not enough data for both headers
    }

    // Check if the protocol in the Ethernet header is IPv4.
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP)) {
        return 0; // Not an IPv4 packet
    }

    // Check if the protocol in the IP header is ICMP.
    if (ip->protocol != IPPROTO_ICMP) {
        return 0; // Not an ICMP packet
    }

    // If we reach here, it's a valid IPv4 ICMP packet.
    return 1; // Valid IPv4 ICMP packet
}

/*
    Basically we want to drop the ICMP ipv4 packets and save in
    a map how many packets we are dropping.
*/
SEC("tc_ingress")
int tc_ingress_f(struct __sk_buff *skb)
{
    if (is_ipv4_icmp(skb)) {
        bpf_printk("An ICMP packet has been received."); 
        __u32 *counter;
        __u32 mapKey = 0;
        // Lookup the appropriate map based on the passed map pointer
        counter = bpf_map_lookup_elem(&dropped_map, &mapKey);
        if (counter)
        __sync_fetch_and_add(counter, 1);
        return TC_ACT_SHOT; // Drop the packet
    }
    return TC_ACT_OK; // Allow the packet
}

