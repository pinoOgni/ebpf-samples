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


struct trace_event_raw_kmalloc {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	u64 bytes_req;
	u64 bytes_alloc;
	long unsigned int gfp_flags;
	int node;
	char __data[0];
};


struct bpf_map_def SEC("maps") memory_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};


SEC("tracepoint/kmem/kmalloc")
void track_kmalloc(struct trace_event_raw_kmalloc *args) {
    u32 key = 0; // Key for kmalloc
    u64 size = args->bytes_alloc; // Size allocated
    // Update the memory_map with the allocated size
    u64 *value = bpf_map_lookup_elem(&memory_map, &key);
    if (value) {
        *value += size; // Increment the value
    } else {
        u64 initial_value = size;
        bpf_map_update_elem(&memory_map, &key, &initial_value, BPF_ANY);
    }
}
