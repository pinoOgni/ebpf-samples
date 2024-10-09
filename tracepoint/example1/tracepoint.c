//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); 
    __type(value, __u64);
} counter SEC(".maps");


// trace the entry to the openat syscall
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    // eBPF has restrictions on strings and loops
    // so staticaly declare size and string upfront
    const int test_len = 5;
    const char test[test_len] = "test";
    char comm[test_len];

    // Use helper to get executable name:
    bpf_get_current_comm(&comm, sizeof(comm));
    // check to see if name matches
    for (int i = 0; i < test_len; i++) {
        if (test[i] != comm[i]) {
            // Name missmatch,
            // return and don't do anything
            return 0;
        }
    }

    // executable name is 'test', log event,
    // perform additional checks, to do anything else

    // uncomment if you want 
    //bpf_printk("comm is %s\n",comm);
    u32 key = 0;
    u64 initval = 1, *valp;

    valp = bpf_map_lookup_elem(&counter, &key);
    if (!valp) {
        bpf_map_update_elem(&counter, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);

    return 0;
}
