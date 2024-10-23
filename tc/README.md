# TC (Traffic Control)


In this section, we will explore some programs related to TC, or Traffic Control, in Linux. This is a crucial subsystem that plays a significant role in network management, though it can also be quite complex and challenging to work with.


### Table Of Contents

* [Example 0](#example-0)
* [Example 1](#example-1)
* [Example 2](#example-2)
* [Example 3](#example-3)
* [Example 3 cBPF](#example-3-cbpf)
* [Experiments](#experiments)
* [Useful stuff](#useful-stuff)



### [Example 0](./example0)

To start off on the right foot, I preferred to thoroughly review everything related to TC and eBPF TC. In particular, the Cilium guide seems very interesting, and in this first example—actually Example 0—I will simply follow their guidance.

In particular I'm talking about this part "Multiple programs can reside inside a single C file in different sections." that can be find [here](https://docs.cilium.io/en/latest/bpf/toolchain/#bpf-dev). 

**Actually I started from this but then I needed to change both code and commands both for some errors like the following and also to something simpler in this example:**
```
sudo tc filter add dev em1 ingress bpf da obj tc-example.o sec ingress
libbpf: elf: legacy map definitions in 'maps' section are not supported by libbpf v1.0+
ERROR: opening BPF object file failed
Unable to load program
```
Or 
```
# if -g flag is not used 
sudo tc filter add dev em1 ingress bpf da obj tc-example.o sec ingress
libbpf: BTF is required, but is missing or corrupted.
ERROR: opening BPF object file failed
Unable to load program
```

This example is counting the byts in ingress and in egress and save it in 2 separated maps.

So these are the commands:
```
# Create a small testbed (ns1[em1]---[em2]ns2)
sudo ip link add name em1 type veth peer name em2

sudo ip netns add ns1
sudo ip netns add ns2

sudo ip link set em1 netns ns1
sudo ip link set em2 netns ns2

sudo ip netns exec ns1 ip link set dev em1 up
sudo ip netns exec ns2 ip link set dev em2 up

sudo ip netns exec ns1 ip addr add 10.0.0.1/24 dev em1
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev em2

# ebpf code
clang -g -O2 -Wall --target=bpf -I/usr/include/bpf -c tc-example.c -o tc-example.o

sudo ip netns exec ns1 tc qdisc add dev em1 clsact
sudo ip netns exec ns1 tc filter add dev em1 ingress bpf da obj tc-example.o sec ingress
sudo ip netns exec ns1 tc filter add dev em1 egress bpf da obj tc-example.o sec egress


sudo ip netns exec ns1 tc filter show dev em1 ingress             
# filter protocol all pref 49152 bpf chain 0 
# filter protocol all pref 49152 bpf chain 0 handle 0x1 tc-example.o:[ingress] direct-action not_in_hw id 168 name tc_ingress tag c5f7825e5dac396f jited 


sudo ip netns exec ns1 tc filter show dev em1 egress 
# filter protocol all pref 49152 bpf chain 0 
# filter protocol all pref 49152 bpf chain 0 handle 0x1 tc-example.o:[egress] direct-action not_in_hw id 172 name tc_egress tag c5f7825e5dac396f jited

```

We can also check this:
```
$ sudo bpftool prog show
124: sched_cls  name tc_ingress  tag c5f7825e5dac396f  gpl
        loaded_at 2024-10-16T20:14:27+0200  uid 0
        xlated 152B  jited 89B  memlock 4096B  map_ids 26
        btf_id 335
128: sched_cls  name tc_egress  tag c5f7825e5dac396f  gpl
        loaded_at 2024-10-16T20:14:40+0200  uid 0
        xlated 152B  jited 89B  memlock 4096B  map_ids 29
        btf_id 344

$ sudo bpftool map show
26: array  name ingress_map  flags 0x0
        key 4B  value 4B  max_entries 1  memlock 328B
        btf_id 335
29: array  name egress_map  flags 0x0
        key 4B  value 4B  max_entries 1  memlock 328B
        btf_id 344
```

To test it:
```
# watch the ingress_map
sudo bpftool map dump id 26
# watch the egress_map
sudo bpftool map dump id 29
```
Use `ping` to generate traffic:
```
# to trigger both the egress (echo request) and ingress (echo reply) tc ebpf program on em1
sudo ip netns exec ns1 ping 10.0.0.2

# to trigger only the egress tc ebpf program on em1
sudo ip netns exec ns1 ping 10.0.0.3

# to trigger only the ingress tc ebpf program on em1
sudo ip netns exec ns2 ping 10.0.0.3
```


### [Example 1](./example1)


This example uses the TC ingress hook to drop only ICMP packets, and it stores a counter of the dropped packets in a eBPF map. 

The testing process is similar to the previous example, with some additional considerations discussed at the end.

So these are the commands:
```
# Create a small testbed (ns1[em1]---[em2]ns2)
sudo ip link add name em1 type veth peer name em2

sudo ip netns add ns1
sudo ip netns add ns2

sudo ip link set em1 netns ns1
sudo ip link set em2 netns ns2

sudo ip netns exec ns1 ip link set dev em1 up
sudo ip netns exec ns2 ip link set dev em2 up

sudo ip netns exec ns1 ip addr add 10.0.0.1/24 dev em1
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev em2

# ebpf code
clang -g -O2 -Wall --target=bpf -I/usr/include/bpf -c tc-example.c -o tc-example.o

sudo ip netns exec ns1 tc qdisc add dev em1 clsact
sudo ip netns exec ns1 tc filter add dev em1 ingress bpf da obj tc-example.o sec ingress


sudo ip netns exec ns1 tc filter show dev em1 ingress             
# filter protocol all pref 49152 bpf chain 0 
# filter protocol all pref 49152 bpf chain 0 handle 0x1 tc-example.o:[ingress] direct-action not_in_hw id 180 name tc_ingress tag 4b995940f4667791 jite

```

We can also check this:
```
$ sudo bpftool prog show
180: sched_cls  name tc_ingress  tag 4b995940f4667791  gpl
	loaded_at 2024-10-17T19:14:24+0200  uid 0
	xlated 248B  jited 148B  memlock 4096B  map_ids 33
	btf_id 366

$ sudo bpftool map show
33: array  name dropped_map  flags 0x0
	key 4B  value 4B  max_entries 1  memlock 328B
	btf_id 366
```

To test it:
```
# watch the ingress_map
sudo bpftool map dump id 26
# watch the egress_map
sudo bpftool map dump id 29
```
Use `ping` to generate traffic:
```
# to trigger the ingress tc ebpf program on em1 (the icmp echo request will be blocked)
sudo ip netns exec ns2 ping 10.0.0.1
# to trigger the ingress tc ebpf program on em1 (the icmp echo reply will be blocked)
sudo ip netns exec ns1 ping 10.0.0.2

# see the dropped counter map
watch sudo bpftool map dump id 33

# try to use tcpdump and see that the packets are dropped
sudo ip netns exec ns1 tcpdump -i em1 -vvv

# if you delete the ebpf probe the tcpdump will capture packets
# and there will be also the echo reply from the ping command
sudo ip netns exec ns1 tc filter del dev em1 ingress pref 49152
```

### [Example 2](./example2/)

This program demonstrates how to load and attach a TC eBPF program to an already
created interface using the cilium/ebpf and florianl/go-tc pkgs.

As you may notice, in the go:generate there is a dropicmp, this means that the
autogenerated files and many autogenerated structured will have this dropicmp prefix.

Basically for the tc part i'm using this [example](https://github.com/florianl/go-tc/blob/1f6cf4701feb4f6aaaf1fb50f11676b8090cc9ec/example_gteq_1.16_test.go#L22)
thanks to [florianl](https://github.com/florianl). 
In this example he is creating a dummy interface and he is attaching a tc ebpf program that
is return 0 (`TC_ACT_OK`).

The ebpf code is this example2 is the same as example1.

To test it I chose to create a simple testbed where we have `(default ns)[veth1]---[veth2](ns2)`
We will put the TC ebpf program on the ingress of `veth1` that is in the default ns
and then ping from ns2 to see that all icmp echo request packets are dropped or also we can ping
from the default ns to see that all the icmp echo reply packets are dropped.

These are the commands to test it:

```
sudo ip link add name veth1 type veth peer name veth2
sudo ip netns add ns2
sudo ip link set veth2 netns ns2
sudo ip netns exec ns2 ip link set dev veth2 up
sudo ip link set veth1 up
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2
sudo ip addr add 10.0.0.1/24 dev veth1

# launch the ping command
sudo ip netns exec ns2 ping 10.0.0.1

# in another terminal
cd ebpf-examples
sudo ./tc/example2/bin/example2
```

We can see that that are no more echo reply packets.

Now we can stop the program and then remove the `clasct` and we can see the echo reply packets:

```
sudo tc qdisc del dev veth1 clsact
```

We can now delete the testbed (the `veth1` peer in the `default ns` is automatically deleted):
```
sudo ip netns del ns2
```


### [Example 3](./example3/)

This example is similar to example2, but it includes handling SIGINT and SIGTERM signals, ensuring that the `clsact` is automatically deleted before the program exits. We only need to delete the testbed manually.


So, as before, these are the commands to test it:

```
sudo ip link add name veth1 type veth peer name veth2
sudo ip netns add ns2
sudo ip link set veth2 netns ns2
sudo ip netns exec ns2 ip link set dev veth2 up
sudo ip link set veth1 up
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2
sudo ip addr add 10.0.0.1/24 dev veth1

# launch the ping command
sudo ip netns exec ns2 ping 10.0.0.1

# in another terminal
cd ebpf-examples
sudo ./tc/example3/bin/example3
```

We can see that that are no more echo reply packets.

Now we can stop the program and then remove the `clasct` and we can see the echo reply packets:

```
sudo tc qdisc del dev veth1 clsact
```

We can now delete the testbed (the `veth1` peer in the `default ns` is automatically deleted):
```
sudo ip netns del ns2
```

### [Example 3 cBPF](./example3_cBPF/)

In this example, I simply wanted to experiment with TC while using a BPF filter written as if we were using tcpdump. Basically, all ICMP traffic is dropped. To test it, we can follow the instructions from the previous example with one difference, which is the type of qdisc used.

```
sudo ip link add name veth1 type veth peer name veth2
sudo ip netns add ns2
sudo ip link set veth2 netns ns2
sudo ip netns exec ns2 ip link set dev veth2 up
sudo ip link set veth1 up
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2
sudo ip addr add 10.0.0.1/24 dev veth1

# add manually the qdisc in ingress
sudo tc qdisc add dev veth1 ingress

# launch the ping command
sudo ip netns exec ns2 ping 10.0.0.1

# in another terminal
cd ebpf-examples
sudo ./tc/example3_cBPF/bin/example3_cBPF

```
We can see that the traffic is dropped.

We can also check: `tc filter show dev veth1 ingress` to have more information.

We can now delete the testbed (the `veth1` peer in the `default ns` is automatically deleted):
```
sudo ip netns del ns2
```


### [Experiments](./experiments/)

Here I'll add the various experiments I'm doing, both with eBPF and also incorporating other things as I study them and see things that interest me and that I want to have memory of in the future.

1. [clsact_prio](./experiments/clsact_prio/): In this example, I wanted to try attaching an eBPF program to the egress path using a `clsact` qdisc, and a cBPF program (filter with action) using a `prio` qdisc, which, as far as I understand, is only for egress. For more information, I have added a [README](./experiments/clsact_prio/README.md) in the example directory.
1. [cbpf_ebpf_clsact](./experiments/cbpf_ebpf_clsact/): In this example, I wanted to try using a clsact and attaching two filters. The first (a modified version of a previous example) is an eBPF program that counts the packets it receives; the second is a cBPF filter written in tcpdump style, which captures only ICMP traffic. Since I attach the eBPF program first and then the cBPF filter, the priority is set automatically (I still don't know how to set it manually). As a result, the second filter will have a lower priority number than the first, giving it higher effective priority. I still need to investigate the action defined in the cBPF filter.


### Useful stuff

* [This](https://patchwork.ozlabs.org/project/netdev/patch/61198814638d88ce3555dbecf8ef875523b95743.1452197856.git.daniel@iogearbox.net/) is interesting and it talks about the `clsact`. 
* https://github.com/torvalds/linux/blob/master/include/uapi/linux/pkt_cls.h
* [Cilium guide for TC](https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control)