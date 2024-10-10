# tracepoint examples

This directory is used only for tracepoint examples.

### Table Of Contents

* [Example 1](#example-1)
* [Example 2](#example-2)


### [Example 1](./example1/)

This example attaches an eBPF program to the sys_enter_openat system call using a tracepoint. Instead of counting all executions of the sys_enter_openat call, it only counts the instances where the executable's name is 'test,' incrementing a counter in a map.

In the example1 directory is present also a "test" directory with a simple Hello World go example, you can build it and run it './test` to check that the ebpf program is working.


### [Example 2](./example2/)

Basically is almost the same as example1.

This example attaches an eBPF program to the sys_enter_execve system call using a tracepoint. Instead of counting all executions of the sys_enter_execve call, it only counts the instances where the executable's name is 'cat', like 'cat test' incrementing a counter in a map.