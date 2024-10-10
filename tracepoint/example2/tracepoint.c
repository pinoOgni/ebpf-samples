//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define BUF_SIZE 256       // Define your buffer size
#define COMMAND_LEN 3     // Length of the command "cat"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); 
    __type(value, __u64);
} counter SEC(".maps");


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

// Helper function to check if the substring "test" is present in the buffer
static __inline int has_test(const char *buf) {
    const char pattern[] = "test";
    for (int i = 0; i < BUF_SIZE - 4; i++) {
        if (buf[i] == 't' && buf[i+1] == 'e' && buf[i+2] == 's' && buf[i+3] == 't') {
            return 1;
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    char prog_name[BUF_SIZE];
    const char cat[COMMAND_LEN] = "cat";
    int found = 0; // Flag to indicate if "cat" is found

    // Read the program name from the first argument
    bpf_probe_read_user(prog_name, BUF_SIZE, (void *)ctx->args[0]);

    // Check if "cat" is in prog_name
    for (int i = 0; i < BUF_SIZE - COMMAND_LEN; i++) {
        found = 1; // Assume we found "cat"
        
        // Check each character in "cat"
        for (int j = 0; j < COMMAND_LEN; j++) {
            // If characters don't match, set found to 0 and break
            if (prog_name[i + j] != cat[j]) {
                found = 0;
                break; // Break inner loop
            }
        }

        // If "cat" was found, print the message and return
        if (found) {
            u32 key = 0;
            u64 initval = 1, *valp;

            valp = bpf_map_lookup_elem(&counter, &key);
            if (!valp) {
                bpf_map_update_elem(&counter, &key, &initval, BPF_ANY);
                return 0;
            }
            __sync_fetch_and_add(valp, 1);
            //bpf_printk("Matched program name: %s\n", prog_name);
            return 0; // Exit after finding the match
        }
    }

    return 0; // Return if "cat" is not found
}
