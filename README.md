# ebpf-samples

This repo contains various examples to learn, explore, and experiment with eBPF and not only. I would like to go deeper both in the controlplane and dataplane part. 


### Repository Organization

1. **headers**: Contains various header files used across the programs in this repository.
2. **vmlinux**: Holds the `vmlinux` BTF file, generated with `bpftool` for compatibility with the kernel used in development.
3. **xdp**: Includes eBPF XDP (eXpress Data Path) program examples. Each example either builds on previous ones or explores similar concepts.
4. **tracepoint**: Features examples related to tracepoints, including syscall and networking-based examples.
5. **tc**: Contains Traffic Control (TC) examples.
6. **tc/experiments**: This subdirectory includes experimental TC examples that are in an exploratory or developmental phase.

### How to Use It

Use the provided Makefile to build and run examples. For instance:

```sh
make run TARGET=xdp/example1
```

This command uses `go generate` to prepare files from C code, builds the binary, and executes it.

Attention: it will not work for all examples. Indeed there are examples with no go code!

### Notes

* This repository primarily uses the [cilium/ebpf](https://github.com/cilium/ebpf) library, with some headers adapted from this library for specific needs. Future examples may incorporate `libbpf`.
* I write these examples in my free time, after work or on weekends. There may be some mistakes, but that's the value of open source: making code accessible and open for everyone to learn from and improve.

### Contributing

* **Feedback and Contributions**: Contributions are welcome! If you’d like to add an example or improve an existing one, please submit a pull request or open an issue.
* **Experimental Code**: The `tc/experiments` folder contains examples in development, so these may change frequently as I refine the code.

