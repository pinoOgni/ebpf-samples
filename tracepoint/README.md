# tracepoint examples

This directory contains tracepoint examples.

### Table Of Contents

* [Example 1](#example-1)
* [Example 2](#example-2)
* [Example 3](#example-3)
* [Example 4](#example-4)
* [Example 5](#example-5)
* [Example 6](#example-6)
* [Example 7](#example-7)
* [Useful Stuff](#useful-stuff)

### [Example 1](./example1/)

This example attaches an eBPF program to the `sys_enter_openat` system call using a tracepoint. Instead of counting all executions of the `sys_enter_openat` call, it only counts instances where the executable's name is 'test,' incrementing a counter in a map.

The `example1` directory also contains a "test" directory with a simple *Hello World Go* example. You can build and run it with `./test` to check that the  eBPF program is working.


### [Example 2](./example2/)

This example is very similar to example1.

It attaches an eBPF program to the `sys_enter_execve` system call using a tracepoint. Instead of counting all executions of the `sys_enter_execve` call, it only counts instances where the executable's name is 'cat,' like 'cat test,' incrementing a counter in a map.


### [Example 3](./example3/)

This example attaches an eBPF program to 2 syscalls: `sys_enter_sendto` and `sys_enter_recvfrom`. It counts the number of incoming and outgoing packets that are sent or received using the previous system calls. So this example is just to use 2 tracepoints in one program.

For example, the `ping` tool is using the `sys_enter_sendto` system call so you can use it to test and see the outgoing packets. 


### [Example 4](./example4/)

This example attaches an eBPF program to the `sys_enter_sendto` syscall. It counts the number of outgoing packets for each IP destination address and prints the results.

Notes:
1. You could also try to use the `sys_enter_recvfrom` syscall to count the incoming packets for each IP source address.
2. The map iteration approach is good for simplicity and ease of implementation but may become less effective in high-performance or real-time scenarios. Indeed iterating over the entire map can become inefficient if the map contains a large number of entries.

### [Example 5](./example5/)

This example tracks how many times binaries have been executed by the user "ebpf-pino" (created with UID 1001). We attach a tracepoint to the `sys_enter_execve` syscall, which is triggered when a process attempts to execute a binary. When the syscall is invoked, our eBPF program reads the arguments passed to it, specifically focusing on the command being executed. There is a map to store the binary path as key and a counter as the value. 

Notes: 
* Some commands, like `pwd` and `cd`, are built-in commands in most shells, it means that they are executed directly by the shell rather than calling an external binary. As a result, they do not generate an `execve` syscall and instead manipulate the shell's environment directly. Possible solutions could involve tracking when the shell is invoked or when it processes commands, or using other tracepoints like `sys_exit` (though this may be complex and is still a **TODO**).
* Same considerations as examle4 about the map iteration.

How to use it: create a new user (or use it if you already have a user with UID 1001), for example, by running `sudo usermod -aG sudo ebpf-pino`, and then switch to that user with `su - ebpf-pino`. Now, as a sudo user, execute the `example5` binary. 

Question: what happens if you type a command that does not exist, such as `ciao` (which means 'hello' in Italian)?

### [Example 6](./example6/)

This example tracks the total bytes allocated by the kernel's memory allocator by attaching an eBPF program to the `kmem/kmalloc` tracepoint.

### [Example 7](./example7/)

This example attaches an eBPF program to 2 tracepoints that count sent (`net_dev_xmit`) and received (`netif_rx`) packets. 

I used a `per-CPU hash map` to add something different compared to other examples. The tracepoints trigger on packet send and receive, but only update the map if the task's PID matches the target PID. The target PID is set from the Go controlplane, based on a given test binary name. 

The test program is a C binary called `icmp_sender` (in the test directory), that sends N ICMP packets using an `AF_PACKET` socket (in my case the test is done with a veth pair, where `veth0` is one of the peer of it).

**Yes, you can use `ping` instead of `icmp_sender`.**

Some other notes:
1. I chose to use only 2 tracepoints just to show the concept, but you can use more of them!
2. For an incoming packet, the order of tracepoints triggered is as follows:
* tracepoint:net:netif_rx_entry
* tracepoint:net:netif_rx
* tracepoint:net:netif_rx_exit
* tracepoint:net:netif_receive_skb
3. For an outgoing packet, the order of tracepoints triggered is as follows:
* tracepoint:net:net_dev_queue
* tracepoint:net:net_dev_start_xmit
* tracepoint:net:net_dev_xmit
4. Additionally, the following tracepoints should also be considered. However, I need to enable `GRO` (and possibly configure other settings), which is not the case at the moment:
* napi_gro_receive_entry
* napi_gro_receive_exit
* napi_gro_frags_entry
* napi_gro_frags_exit





### Useful Stuff

In this section there is a list of useful links (articles, blogs, docs, videos) about eBPF tracepoints.

* [Program type BPF_PROG_TYPE_TRACEPOINT from docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACEPOINT/)
* **TODO pino** add something else.