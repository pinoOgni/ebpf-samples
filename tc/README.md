# TC (Traffic Control)


In this section, we will explore some programs related to TC, or Traffic Control, in Linux. This is a crucial subsystem that plays a significant role in network management, though it can also be quite complex and challenging to work with.


### Table Of Contents

* [Example 0](#example-0)
* [Example 1](#example-1)

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


### Useful stuff

* [This](https://patchwork.ozlabs.org/project/netdev/patch/61198814638d88ce3555dbecf8ef875523b95743.1452197856.git.daniel@iogearbox.net/) is interesting and it talks about the `clsact`. 
* https://github.com/torvalds/linux/blob/master/include/uapi/linux/pkt_cls.h
* [Cilium guide for TC](https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control)