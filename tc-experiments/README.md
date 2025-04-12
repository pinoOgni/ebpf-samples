# TC (Traffic Control) Experiments

In this section, we will do some experiments with the TC subsystem. If you are looking for normal TC examples, please refer to the [tc](../tc/) folder.

### Table Of Contents

* [Experiments](#experiments)
* [Useful stuff](#useful-stuff)



### [Experiments]

Here I'll add the various experiments I'm doing, both with eBPF and also incorporating other things as I study them and see things that interest me and that I want to have memory of in the future.

1. [clsact_prio](./clsact_prio/): In this example, I wanted to try attaching an eBPF program to the egress path using a `clsact` qdisc, and a cBPF program (filter with action) using a `prio` qdisc, which, as far as I understand, is only for egress. For more information, I have added a [README](./clsact_prio/README.md) in the example directory.
1. [cbpf_ebpf_clsact](./cbpf_ebpf_clsact/): In this example, I wanted to try using a clsact and attaching two filters. The first (a modified version of a previous example) is an eBPF program that counts the packets it receives; the second is a cBPF filter written in tcpdump style, which captures only ICMP traffic. Since I attach the eBPF program first and then the cBPF filter, the priority is set automatically (I still don't know how to set it manually). As a result, the second filter will have a lower priority number than the first, giving it higher effective priority. I still need to investigate the action defined in the cBPF filter.



### Useful stuff

This is a list of links to documents, videos, etc. that may be useful. Personally I haven't paid attention to them all so I might remove some in the future:
* [This](https://patchwork.ozlabs.org/project/netdev/patch/61198814638d88ce3555dbecf8ef875523b95743.1452197856.git.daniel@iogearbox.net/) is interesting and it talks about the `clsact`. 
* https://github.com/torvalds/linux/blob/master/include/uapi/linux/pkt_cls.h
* [Cilium guide for TC](https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control)
* [QoS in Linux with TC and Filters](https://www.linux.com/training-tutorials/qos-linux-tc-and-filters/)
* [Linux tc and eBPF. Daniel Borkmann](https://archive.fosdem.org/2016/schedule/event/ebpf/attachments/slides/1159/export/events/attachments/ebpf/slides/1159/ebpf.pdf)
* [Linux Advanced Routing & Traffic Control HOWTO](https://tldp.org/HOWTO/Adv-Routing-HOWTO/index.html)
* [florianl/go-tc Github](https://github.com/florianl/go-tc/tree/main)
* [tc(8) — Linux manual page](https://man7.org/linux/man-pages/man8/tc.8.html)
* [tc-bpf(8) — Linux manual page](https://man7.org/linux/man-pages/man8/tc-bpf.8.html)
* [eBPF Tutorial by Example 20: tc Traffic Control](https://eunomia.dev/tutorials/20-tc/)
* [ebpf docs: Program type BPF_PROG_TYPE_SCHED_CLS](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/)
* [net, sched: add clsact qdisc](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1f211a1b929c804100e138c5d3d656992cfd5622)
* [ Netdev 0.1 - Linux Traffic Control Classifier-Action Subsystem Architecture ](https://www.youtube.com/watch?v=cyeJYjZHv5M)
* [ Understanding the Concepts of Traffic Control ](https://www.youtube.com/watch?v=s6Ays3NNxig)
* [Understanding tc “direct action” mode for BPF. Quentin Monnet](https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/)
* [tc-bpf behavior](https://gist.github.com/anfredette/732eeb0fe519c8928d6d9c190728f7b5)
* [eBPF Qdisc: A Generic Building Block for Traffic Control](https://netdevconf.org/0x17/docs/netdev-0x17-paper37-talk-slides/eBPF%20Qdisc.pdf)


