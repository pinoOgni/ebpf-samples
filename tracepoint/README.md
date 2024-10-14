# tracepoint examples

This directory is used only for tracepoint examples.

### Table Of Contents

* [Example 1](#example-1)
* [Example 2](#example-2)
* [Example 3](#example-3)
* [Example 4](#example-4)
* [Example 5](#example-5)
* [Example 6](#example-6)



* [Useful stuff](#useful-stuff)

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

### [Example 5](./example5/)

This examples is tracking how many times binaries have been executed by the user "ebpf-pino" (created by me and with uid 1001). We can attach a tracepoint to the `sys_enter_execve` syscall, which is triggered when a process attempts to execute a binary. When the syscall is invoked, our eBPF program reads the arguments passed to it, specifically focusing on the command being executed.

There is a map to store the binary path as key and a counter as the value. 

Notes: 
* There are some binaries like `pwd` and `cd` that are built-in commands in most shells. This means they are executed directly by the shell rather than calling an external binary. As a result, they do not generate an `execve` syscall. Instead, they manipulate the shell's environment directly. So, what we can do?  Instead of just focusing on the `execve` syscall, we could track when the shell itself is invoked or when it processes commands (it could be complexx, I guess). Or maybe we can use other tracepoints like `sys_exit` and `sys_exit`. (It's a TODO).
* Same considerations as examle4 about the map iteration.

How to use it: create a new user (or use it if you already have a user with UID 1001), for example, by running `sudo usermod -aG sudo ebpf-pino`, and then switch to that user with `su - ebpf-pino`. Now, as a sudo user, execute the `example5` binary. 

Question: what happens if you type a command that does not exist, such as `ciao` (which means 'hello' in Italian)?

### [Example 6](./example6/)

This example tracks the total bytes allocated by the kernel's memory allocator by attaching an eBPF program to the `kmem/kmalloc`tracepoint.



### Useful stuff

In this section there is a list of useful links (artciles, blogs, docs, videos) about eBPF tracepoints.

* [Program type BPF_PROG_TYPE_TRACEPOINT from docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACEPOINT/)
* 