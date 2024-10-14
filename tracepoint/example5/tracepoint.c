//go:build ignore

#include "common.h"
#include "bpf_tracing.h"


char LICENSE[] SEC("license") = "GPL";

#define MAX_FILENAME_LEN 256

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};

struct bpf_map_def SEC("maps") exec_count_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = MAX_FILENAME_LEN,
    .value_size = sizeof(u64),
    .max_entries = 1024,
};

SEC("tracepoint/syscalls/sys_enter_execve")
int count_execve(struct trace_event_raw_sys_enter *ctx) {
    char binary_name[MAX_FILENAME_LEN] = {};
    u64 *value = 0;
    u64 initValue = 1; // not 0

    // Get the current UID
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Filter by user "ebpf-pino", assuming UID = 1001
    if (uid != 1001) {
        return 0; // Not the correct user so we can skip
    }

    // Retrieve the binary path from syscall arguments (first argument of execve)
    const char *user_binary = (const char *)(ctx->args[0]);

    // Check if the user_binary pointer is valid and read the binary name otherwise ebpf verifier gets angry
    if (user_binary && bpf_probe_read_user_str(binary_name, sizeof(binary_name), user_binary) > 0) {
        // Lookup or create an entry in the map for the binary name
        value = bpf_map_lookup_elem(&exec_count_map, binary_name);
        if (!value) {
            // Initialize if not present
            bpf_map_update_elem(&exec_count_map, binary_name, &initValue, BPF_ANY);
            value = &initValue;
        }

        // Increment the execution counter
        (*value)++;

        // Debug: Print the binary name
        //bpf_printk("Executed binary: %s\n", binary_name);
    }

    return 0;
}