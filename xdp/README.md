# xdp examples

This directory is used only for xdp examples.

It is present a Makefile that can be used to generate, build or run the example.

### Table Of Contents

* [Example 1](#example-1)
* [Example 2](#example-2)
* [Example 3](#example-3)
* [Example 4](#example-4)


### [Example 1](./example1/README.md)

This program basically is a xdp probe that counts the number of IPv4 packet. It checks if it is ethernet, ipv4 and not malformed. The controlplane reads the value from an array map.


### [Example 2](./example2/)

This program is similar to example 1 but designed for IPv6. To achieve this, I added a struct for the IPv6 header in the `common.h` header file, along with the value for the IPv6 protocol found within the Ethernet header.

### [Example 3](./example3/)

This program is the same as example 2 but instead of using `common.h` it uses `vmlinux.h`. 

To generate the `vmlinux.h` file you can use bpftool: `bpftool btf dump file /sys/kernel/btf/vmlinux form c >> vmlinux.h`.

