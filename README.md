# ebpf-samples

This repo contains various examples to learn, explore, and experiment with eBPF and not only. I would like to go deeper both in the controlplane and dataplane part.

In this repo, I will add various eBPF examples starting with simple ones and gradually add more complex examples. 

Some of the eBPF code may be adapted from well-known repositories.

### Repo organization


Here’s a translation for your GitHub repository description:

---

# Repository Overview

This repository is organized as follows:

1. **headers**: This directory contains various header files that will be used in the different programs.
2. **vmlinux**: This folder contains the vmlinux generated with bpftool for the kernel I am working on.
3. **xdp**: This section includes examples of eBPF XDP programs. Each example builds upon the complexity of the previous one or is similar in nature.
4. **tracepoint**: This directory features various examples related to tracepoints, including those for syscalls, networking, and more.
5. **tc**: This contains examples of the TC (Traffic Control) subsystem.

--- 

Feel free to modify it as needed!


### How to use it

You can use the provided Makefile to generate, build and run the example. For example:
```
make run TARGET=xdp/example1
```
This command will generate the necessary file from the C code (using go generate), then it will build the binary and execute it.


### Notes 

I'm using the [cilium/ebpf](https://github.com/cilium/ebpf) library. Maybe I'll add some example with libbpf. The headers used are taken from the same library and I added some modifications.


