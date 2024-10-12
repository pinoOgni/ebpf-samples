//go:build ignore

#include "common.h"

// from linux/socket.h
#define AF_INET		2	/* Internet IP Protocol 	*/

char LICENSE[] SEC("license") = "GPL";

// Instead of include the all vmlinux.h
typedef short unsigned int __kernel_sa_family_t;

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
};

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

// Define a map to count packets sent per destination IP address (IPv4)
struct bpf_map_def SEC("maps") packet_count_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),  // IPv4 addresses
    .value_size = sizeof(u64), // Counter
    .max_entries = 1024,      // Maximum number of IPs we want to track
};

// We can try to do the same program with sys_enter_recv and source addresses
// eBPF program to track packets sent to different destination addresses
SEC("tracepoint/syscalls/sys_enter_sendto")
int count_packets_by_dest(struct trace_event_raw_sys_enter *ctx)
{
    int ret;
    u64 *counter, init_val = 1;
    u32 dest_ip;

    // The 5th argument to sys_sendto is the destination address (args[4])
    struct sockaddr_in dest_addr = {};

    // Read the destination address (IPv4) from user space
    ret = bpf_probe_read_user(&dest_addr, sizeof(dest_addr), (void *)ctx->args[4]);
    if (ret < 0) {
        return 0; // Unable to read destination address, return
    }

    // Check if it's an IPv4 packet (AF_INET)
    if (dest_addr.sin_family != AF_INET) {
        return 0; // Not IPv4, return
    }

    // Extract the destination IP (in network byte order)
    dest_ip = dest_addr.sin_addr.s_addr;

    // Look up the destination IP in the map
    counter = bpf_map_lookup_elem(&packet_count_map, &dest_ip);
    if (counter) {
        // Increment the existing counter
        __sync_fetch_and_add(counter, 1);
    } else {
        // Initialize the counter for this IP address
        bpf_map_update_elem(&packet_count_map, &dest_ip, &init_val, BPF_ANY);
    }

    return 0;
}