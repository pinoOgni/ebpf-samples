# kprobe examples

This directory contains krpobe examples.

### Table Of Contents

* [Introduction](#introduction)
* [Example 1](#example-1)
* [Useful Stuff](#useful-stuff)


### Introduction


A wonderful explanation about kprobe is [here](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/) so I would like to focus on other things.

Let's say that we want to write an ebpf kprobe program, the first thing we need to do is to see the list of kprobe hooks available and to do that we need to do `cat /sys/kernel/debug/tracing/available_filter_functions` that is a very long list of all kernel functions where is it possible to attach a kprobe. 

Another thing we can do is `cat /sys/kernel/debug/kprobes/list` which shows the list of all registered kprobes, it means that if we attach an `BPF_PROG_TYPE_KPROBE` ebpf program type this list is populated.

That file shows "classic" kprobes, set via the older kprobes API (like `register_kprobe()` in the kernel or perf probe).
However, tools like pwru (and many modern tracing tools using libbpf) use eBPF kprobes, which are implemented via `bpf_attach_kprobe()`. 
Those do not show up in kprobes/list, but they are active and loaded into the kernel.

Another interesting file is `/proc/kallsyms` which is a really long file which provides a symbol table for the kernel. An example is: 

```
sudo cat /proc/kallsyms | grep tcp_connect
ffffffff9f007910 t __pfx_tcp_connect_queue_skb
ffffffff9f007920 t tcp_connect_queue_skb
ffffffff9f00a360 t __pfx_tcp_connect_init
ffffffff9f00a370 t tcp_connect_init
ffffffff9f00ca40 T __pfx_tcp_connect
ffffffff9f00ca50 T tcp_connect
ffffffff9f16c790 t __pfx_mptcp_connect
ffffffff9f16c7a0 t mptcp_connect
ffffffff9f2396fd t tcp_connect_init.cold
ffffffff9f239814 t tcp_connect.cold
ffffffff9f240e8d t mptcp_connect.cold
ffffffff9fdaa6b8 r __ksymtab_tcp_connect
```
It contains the names and memory addresses of all the functions, variables, and other symbols used by the kernel and its modules. 
This file can be used to map kernel addresses to the corresponding symbol names, which is particularly useful for debugging and analyzing kernel code.

**Note**: if you do `cat /proc/kallsyms | grep <function_name>` and you see something like:
```
0000000000000000 t __pfx_tcp_connect_queue_skb
0000000000000000 t tcp_connect_queue_skb
0000000000000000 t __pfx_tcp_connect_init
0000000000000000 t tcp_connect_init
0000000000000000 T __pfx_tcp_connect
```
is because the kernel is hiding symbol addresses for security reasons, more info [here](https://lwn.net/Articles/420403/). 
You can check it with `cat /proc/sys/kernel/kptr_restrict` where:
- `0`: all users can read `/proc/kallsyms`
- `1`: only privileged users with `CAP_SYSLOG` can read it
- `2`: even root sees restricted output



#### What is struct `pt_regs`?

`pt_regs` stands for **Processor Trap Registers** and it's a structure used by the Linux kernel to represent the CPU register state when a trap, interrupt, or syscall occurs.


In kprobe eBPF programs, the Linux kernel passes a pointer to a struct `pt_regs` when a probed function is hit. 
In the context of eBPF kprobes, struct `pt_regs` captures the CPU state at the moment a probed kernel function is entered (or exited).

Depending on the architecture (x86_64, arm64, etc.), the contents and layout of `pt_regs` vary, but it always includes general-purpose registers (like rdi, rsi, rdx, etc. on x86_64), and sometimes special registers (like ip, sp, flags, etc.).

This state includes arguments passed to the function (in registers), so kprobe eBPF programs can access those arguments via `pt_regs`.

To access `pt_regs` we use the macros defined in libbpf [`bpf_tracing.h`](https://github.com/libbpf/libbpf/blob/master/src/bpf_tracing.h).

More info here [BPF_PROG_TYPE_KPROBE context](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/#context) and here [Libbpf eBPF side](https://docs.ebpf.io/ebpf-library/libbpf/ebpf/).



### [Example 1](./example1/)

This program demonstrates how to attach an eBPF program to the `tcp_connect` kernel function. It prints the source and destination ports of a TCP connection to the `trace_pipe` file **ONLY** if either the source or destination port is `5201`. 

Let's test it:
```
cd ebpf-samples
make build TARGET=kprobe/example1
sudo ./kprobe/example1/bin/example1
```
In another terminal, view the trace output:
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
We can use iperf3 to generate a TCP connection:
```
iperf3 -s 
```
Then, in another terminal, we can run the client:
```
iperf3 -c 127.0.0.1 -t 1
```



### Useful Stuff
* https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/
* https://docs.kernel.org/trace/kprobes.html
* https://eunomia.dev/tutorials/2-kprobe-unlink/#kprobe-example
* https://github.com/iovisor/bcc/issues/2073
* https://eyakubovich.github.io/2022-04-19-ebpf-kprobe-params/
* https://nakryiko.com/posts/bpf-core-reference-guide/#bpf-core-read-1
* https://stackoverflow.com/questions/70905815/how-to-read-all-parameters-from-a-function-ebpf
* https://github.com/lizrice/learning-ebpf/blob/main/chapter7/hello.bpf.c
* https://github.com/cilium/ebpf/tree/main/examples/kprobe
* https://github.com/libbpf/libbpf/commit/21ec5ca723c75f3ce351e1280821a643857e144e





