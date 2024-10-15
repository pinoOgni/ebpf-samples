//go:build ignore

#include "common.h"
#include "bpf_tracing.h"


char LICENSE[] SEC("license") = "GPL";


struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_net_dev_template {
	struct trace_entry ent;
	void *skbaddr;
	unsigned int len;
	u32 __data_loc_name;
	char __data[0];
};


struct bpf_map_def SEC("maps") packet_count_map = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 2, // incoming, outgoing
};

struct bpf_map_def SEC("maps") pid_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1, 
};

// Tracepoint program attached to netif_rx
// It will be triggered when a packet is received by the NIC and handed to the network stack
SEC("tracepoint/net/netif_rx")
int count_netif_rx(struct trace_event_raw_net_dev_template *ctx) {
    // Get the PID of the current task
    u32 pid = bpf_get_current_pid_tgid() >> 32; 

    u32 key_pid = 0;
    u32 *target_pid;
    target_pid = bpf_map_lookup_elem(&pid_map, &key_pid);
    if (target_pid && pid == *target_pid) {
        u32 key = 1; // Key for packets received
        u64 *count;

        // Look up the counter in the map
        count = bpf_map_lookup_elem(&packet_count_map, &key);
        if (count) {
            // Increment the counter for received packets
            __sync_fetch_and_add(count, 1);
        }
    }
    return 0;
}


// Tracepoint program attached to netif_dev_xmit
// It will be triggered when the actual transmission occurs 
SEC("tracepoint/net/net_dev_xmit")
int count_netif_xmit(struct trace_event_raw_net_dev_template *ctx) {
    // Get the PID of the current task
    u32 pid = bpf_get_current_pid_tgid() >> 32; 

    u32 key_pid = 0;
    u32 *target_pid;
    target_pid = bpf_map_lookup_elem(&pid_map, &key_pid);
    if (target_pid && pid == *target_pid) {
        u32 key = 0; // Key for packets sent
        u64 *count;

        // Look up the counter in the map
        count = bpf_map_lookup_elem(&packet_count_map, &key);
        if (count) {
            // Increment the counter for sent packets
            __sync_fetch_and_add(count, 1);
        }
    }
    return 0;
}


/*
I chose to use only 2 tracepoints just to show the concept, but you can use more of them!

For an incoming packet, the order of tracepoints triggered is as follows:

* tracepoint:net:netif_rx_entry
* tracepoint:net:netif_rx
* tracepoint:net:netif_rx_exit
* tracepoint:net:netif_receive_skb

For an outgoing packet, the order of tracepoints triggered is as follows:

* tracepoint:net:net_dev_queue
* tracepoint:net:net_dev_start_xmit
* tracepoint:net:net_dev_xmit

Additionally, the following tracepoints should also be considered:

* napi_gro_receive_entry
* napi_gro_receive_exit
* napi_gro_frags_entry
* napi_gro_frags_exit

However, I need to enable GRO (and possibly configure other settings), which is not the case at the moment.
*/