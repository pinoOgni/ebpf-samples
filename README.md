# ebpf-samples

This repo contains various examples to learn, explore, and experiment with eBPF.

In this repo, I will add various eBPF examples. I'll start with simple ones and gradually add more complex examples. Some of the eBPF code may be adapted from well-known repositories.


### How to use it

You can use the provided Makefile to generate, build and run the example. For example:
```
make run TARGET=xdp/example1
```
This command will generate the necessary file from the C code (using go generate), then it will build the binary and execute it.


### Notes 

I'm using the [cilium/ebpf](https://github.com/cilium/ebpf) library. Maybe I'll add some example with libbpf. The headers used are taken from the same library.


