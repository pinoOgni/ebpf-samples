# tracepoint examples

This directory is used only for tracepoint examples.

### Table Of Contents

* [Example 1](#example-1)
* [Example 2](#example-2)
* [Example 3](#example-3)
* [Example 4](#example-4)

### [Example 1](./example1/)

This example attaches an eBPF program to the sys_enter_openat system call using a tracepoint. Instead of counting all executions of the sys_enter_openat call, it only counts the instances where the executable's name is 'test,' incrementing a counter in a map.

In the example1 directory is present also a "test" directory with a simple Hello World go example, you can build it and run it './test` to check that the ebpf program is working.


### [Example 2](./example2/)

Basically is almost the same as example1.

This example attaches an eBPF program to the sys_enter_execve system call using a tracepoint. Instead of counting all executions of the sys_enter_execve call, it only counts the instances where the executable's name is 'cat', like 'cat test' incrementing a counter in a map.


### [Example 3](./example3/)

This example attaches an eBPF program to 2 syscalls: sys_enter_sendto and sys_enter_recvfrom. It is counting the number of incoming and outgoing packets that are sent or received using the previous system calls. So this example is just to use 2 tracepoint in one program.

For example, the `ping` tool is using the sys_enter_sendto system calls so you can use it to test and see the outgoing packets. 


### [Example 4](./example4/)

This example attaches an eBPF program to the sys_enter_sendto syscall. It counts the number of outgoing packets for each IP destination address and prints the results.

Notes:
1. We can try to do the same with the sys_enter_recvfrom syscalls and count the incoming packets for each IP source address.
2. The map iteration approach is good for simplicity and ease of implementation but may become less effective in high-performance or real-time scenarios. Indeed iterating over the entire map can become inefficient if the map contains a large number of entries.