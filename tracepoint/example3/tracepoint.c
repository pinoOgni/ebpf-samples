//go:build ignore

#include "common.h"


char __license[] SEC("license") = "Dual MIT/GPL";

// Define a map to store counters for incoming and outgoing packets.
struct bpf_map_def SEC("maps") packet_counters = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32), // INCOMING, OUTGOING
    .value_size = sizeof(u64), // it's a counter
    .max_entries = 2,
};

// Define keys for incoming and outgoing packet counters.
#define INCOMING 1
#define OUTGOING 2


// Attach to sys_enter_sendto to monitor outgoing packets.
SEC("tracepoint/syscalls/sys_enter_sendto")
int bpf_prog_sendto(struct trace_event_raw_sys_enter *ctx) {
    u64 *counter;
    int key = OUTGOING;

    // Increment the outgoing packet counter.
    counter = bpf_map_lookup_elem(&packet_counters, &key);
    if (!counter) {
        u64 initial_value = 1;
        bpf_map_update_elem(&packet_counters, &key, &initial_value, BPF_ANY);
    } else {
        __sync_fetch_and_add(counter, 1);
    }

    return 0;
}

// Attach to sys_enter_recvfrom to monitor incoming packets.
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int bpf_prog_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    u64 *counter;
    int key = INCOMING;

    // Increment the incoming packet counter.
    counter = bpf_map_lookup_elem(&packet_counters, &key);
    if (!counter) {
        u64 initial_value = 1;
        bpf_map_update_elem(&packet_counters, &key, &initial_value, BPF_ANY);
    } else {
        __sync_fetch_and_add(counter, 1);
    }

    return 0;
}

