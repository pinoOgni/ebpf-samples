# Program Test 

In this directory, you can find (some) eBPF example(s) that use the `BPF_PROG_TEST_RUN` (in newer kernel versions, `BPF_PROG_RUN`). I didn't know it and once I discovered it I wanted to try it. It's cool!

For more information, see [this documentation](https://docs.ebpf.io/linux/syscall/BPF_PROG_TEST_RUN/). In brief, it runs an eBPF program that is already loaded into the kernel one or more times with custom input and provides the output. Using the `cilium/ebpf` library, you can run this with the `func (p *Program) Test(in []byte) (uint32, []byte, error) {...}` function.


### Table Of Contents

* [xdp1](#xdp1)




### [xdp1]

The C code for this XDP program is the same as in [xdp example1](../xdp/example1/). The main difference lies in how the program is executed.

To trigger an XDP eBPF function, we need a packet as input, represented as a `[]byte`. To achieve this, I used a `.pcap` file, read it with the `gopacket` library, and converted the packet data into a `[]byte`. The control plane then simply prints the value of the map that is written by the data plane.




