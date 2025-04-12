# ebpf-samples

This repo contains various examples to learn, explore, and experiment with eBPF and not only. I would like to go deeper both in the controlplane and dataplane part. 


### Repository Organization

1. [**headers**](./headers/): Contains various header files used across the programs in this repository.
2. [**vmlinux**](./vmlinux/): Holds the `vmlinux` BTF file, generated with `bpftool` for compatibility with the kernel used in development.
3. [**xdp**](./xdp/README.md): Includes eBPF XDP (eXpress Data Path) program examples. Each example either builds on previous ones or explores similar concepts.
4. [**tracepoint**](./tracepoint/README.md): Features examples related to tracepoints, including syscall and networking-based examples.
5. [**tc**](./tc/README.md): Contains Traffic Control (TC) examples.
6. [**tc-experiments**](./tc-experiments/): This directory includes experimental TC examples that are in an exploratory or developmental phase.
7. [**program_test**](./program_test/README.md): Here there are some eBPF examples that use the `BPF_PROG_TEST_RUN` (in newer kernel versions, `BPF_PROG_RUN`). I didn't know it and once I discovered it I wanted to try it. It's cool!

### How to Use It

Use the provided Makefile to build and run examples. For instance:

```sh
make run TARGET=xdp/example1
# or if an argument is needed
make run TARGET=xdp/example1 ARGS=veth1
```

The `make run` command first uses `go generate` to generate files from C code and then builds the binary.

**Note**: I usually use the Makefile only for building the program and then run the binary separately. For example:

```sh
make build TARGET=xdp/example1
sudo ip netns exec ns1 ./xdp/example1/bin/example1 veth1
```

This is much more intuitive and, I think also, faster when using namespaces to test the programs.

For complete documentation, please refer to the relevant **README**.

**Attention**: The `Makefile` may not work for all examples, as **some do not contain Go code**!


### Notes

* This repository primarily uses the [cilium/ebpf](https://github.com/cilium/ebpf) library, with some headers adapted from this library for specific needs. Future examples may incorporate `libbpf`.
* I work on these examples in my free time, after work or on weekends. There may be some mistakes, but that’s the value of open source: making code accessible and open for everyone to learn from and improve.
* The repository, and especially the documentation, is a work in progress.


### Contributing

* **Feedback and Contributions**: Contributions are welcome! If you’d like to add an example or improve an existing one, please submit a pull request or open an issue.
* **Experimental Code**: The `tc-experiments` folder contains examples in development, so these may change frequently as I refine the code and learn new things.

