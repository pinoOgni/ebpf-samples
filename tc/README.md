# TC (Traffic Control)


In this section, we will explore some programs related to TC, or Traffic Control, in Linux. This is a crucial subsystem that plays a significant role in network management, though it can also be quite complex and challenging to work with.


### Table Of Contents

* [Example 0](#example-0)

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


So the following commands are the "correct" ones (at least for me).
```
# Create a veth pair
sudo ip link add name em1 type veth peer name em2
sudo ip link set dev em1 up
sudo ip link set dev em2 up

# ebpf code
$ clang -g -O2 -Wall --target=bpf -I/usr/include/bpf -c tc-example.c -o tc-example.o

$ sudo tc qdisc add dev em1 clsact
$ sudo tc filter add dev em1 ingress bpf da obj tc-example.o sec ingress
$ sudo tc filter add dev em1 egress bpf da obj tc-example.o sec egress

$ tc filter show dev em1 ingress
filter protocol all pref 49152 bpf chain 0 
filter protocol all pref 49152 bpf chain 0 handle 0x1 tc-example.o:[ingress] direct-action not_in_hw id 124 tag c5f7825e5dac396f

$ tc filter show dev em1 egress
filter protocol all pref 49152 bpf chain 0 
filter protocol all pref 49152 bpf chain 0 handle 0x1 tc-example.o:[egress] direct-action not_in_hw id 128 tag c5f7825e5dac396f 

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
Use `ping` to generate traffic (to google, they will get lost)
```
# to trigger the ingress tc ebpf program on em1
ping -I em2 8.8.8.8

# to tirgger the egress tc ebpf program on em1
ping -I em1 8.8.8.8
```

In the next example, I will attempt to do something similar but with improved performance.

### Useful stuff

* [This](https://patchwork.ozlabs.org/project/netdev/patch/61198814638d88ce3555dbecf8ef875523b95743.1452197856.git.daniel@iogearbox.net/) is interesting and it talks about the `clsact`. 
* https://github.com/torvalds/linux/blob/master/include/uapi/linux/pkt_cls.h
* [Cilium guide for TC](https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control)