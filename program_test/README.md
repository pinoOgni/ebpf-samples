# Program Test 

In this directory, you can find (some) eBPF example(s) that use the `BPF_PROG_TEST_RUN` (in newer kernel versions, `BPF_PROG_RUN`). I didn't know it and once I discovered it I wanted to try it. It's cool!

For more information, see [this documentation](https://docs.ebpf.io/linux/syscall/BPF_PROG_TEST_RUN/). In brief, it runs an eBPF program that is already loaded into the kernel one or more times with custom input and provides the output. Using the `cilium/ebpf` library, you can run this with the `func (p *Program) Test(in []byte) (uint32, []byte, error) {...}` function.


### Table Of Contents

* [xdp1](#xdp1)
* [xdp2](#xdp2)



### [xdp1](./xdp1/)

The C code for this XDP program is the same as in [xdp example1](../xdp/example1/). The main difference lies in how the program is executed.

To trigger an XDP eBPF function, we need a packet as input, represented as a `[]byte`. To achieve this, I used a `.pcap` file, read it with the `gopacket` library, and converted the packet data into a `[]byte`. The control plane then simply prints the value of the map that is written by the data plane.


### [xdp2](./xdp2/)

The logic is the same as in the previous example, except that the eBPF code is taken from an example of [cilium/ebpf](https://github.com/cilium/ebpf/blob/main/examples/xdp/xdp.c) where packets are counted per source IP address.

It's important to note that XDP works only on ingress, but in this case, both `echo request` and `echo reply` packets will be counted. This is because there is no inherent directionality; the program simply processes a set of bytes representing a packet.

If you use the provided `traffic.pcap` you should see this:
```
...
2024/11/19 19:35:09 Map contents:
        10.0.0.6 => 5
        10.0.0.1 => 4
        10.0.0.3 => 2
        10.0.0.2 => 18
        10.0.0.5 => 4
        10.0.0.4 => 3
```


