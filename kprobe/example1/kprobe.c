//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h" // it is included in common.h so now we need to include it manually
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"


// Same example but with BPF_KPROBE macro
/*
SEC("kprobe/tcp_connect")
int BPF_KPROBE(bpf_tcp_connect, struct sock *sk) {

    // Read source IP (IPv4)
    __u32 saddr = 0;
    bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);

    // Read source port (host byte order)
    __u16 sport = 0;
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);

    // Read destination port (network byte order, needs ntohs)
    __u16 dport = 0;
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = __bpf_ntohs(dport);  // convert to host byte order

    // Filter: check if source or dest port matches 5201
    if (sport != 5201 && dport != 5201) {
        return 0; // skip irrelevant connections
    }

    bpf_printk("TCP connect from port %d to port %d (source IP: %x)\n", sport, dport, saddr);

    return 0;
}
*/

// tcp_connect is a classic and powerful way to trace outgoing TCP connections initiated by the host
// https://elixir.bootlin.com/linux/v6.8/source/net/ipv4/tcp_output.c#L4022
SEC("kprobe/tcp_connect")
int bpf_tcp_connect(struct pt_regs *ctx) {
    // CPU register snapshot when tcp_connect is triggered
    // the provided macro extracts the first (and only) argument of 
    // the tcp_connect which is a pointer to a struct sock
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    // Read source IP (IPv4)
    __u32 saddr = 0;
    bpf_core_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);

    // Read source port (host byte order)
    __u16 sport = 0;
    bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);

    // Read destination port (network byte order, needs ntohs)
    __u16 dport = 0;
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = __bpf_ntohs(dport);  // convert to host byte order

    // Filter: check if source or dest port matches 5201
    if (sport != 5201 && dport != 5201) {
        return 0; // skip irrelevant connections
    }

    bpf_printk("TCP connect from port %d to port %d (source IP: %x)\n", sport, dport, saddr);

    return 0;
}


char __license[] SEC("license") = "Dual MIT/GPL";