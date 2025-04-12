# cBPF and eBPF together with a clsact

In this example, I wanted to try using a clsact and attaching two filters. The first (a modified version of a previous example) is an eBPF program that counts the packets it receives; the second is a cBPF filter written in tcpdump style, which captures only ICMP traffic. Since I attach the eBPF program first and then the cBPF filter, the priority is set automatically (I still don't know how to set it manually). As a result, the second filter will have a lower priority number than the first, giving it higher effective priority. I still need to investigate the action defined in the cBPF filter.


To test it:
1. build it:
```
go generate .
go build -a -o bin/ .
```

2. create the usual testbed
```
sudo ip link add name veth1 type veth peer name veth2
sudo ip netns add ns2
sudo ip link set veth2 netns ns2
sudo ip netns exec ns2 ip link set dev veth2 up
sudo ip link set veth1 up
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2
sudo ip addr add 10.0.0.1/24 dev veth1
```
3. Check the connection:
```
# in one terminal
ping 10.0.0.2

# in another terminal
sudo ip netns exec ns2 tcpdump -i veth2 -vvv
```
4. Run the `cbpf_ebpf_clsact` program alone. We should have the same result.
```
sudo ip netns exec ns2 ./bin/cbpf_ebpf_clsact
```
5. The cBPF filter is `icmp[icmptype] == icmp-echo && src host 10.0.0.1` so is will capture only this traffic.
It means that if we do `ping 10.0.0.2` the counter will increment and if we do `sudo ip netns exec ns2 ping 10.0.0.1` the counter will not increment.
There is no drop so the ping will work in both cases.

We can also check:
```
sudo ip netns exec ns2 tc filter show dev veth2 ingress
filter protocol all pref 49151 bpf chain 0 
filter protocol all pref 49151 bpf chain 0 handle 0x2 not_in_hw bytecode '6,40 0 0 12,21 0 3 2048,48 0 0 23,21 0 1 1,6 0 0 65535,6 0 0 0'
filter protocol all pref 49152 bpf chain 0 
filter protocol all pref 49152 bpf chain 0 handle 0x1 direct-action not_in_hw id 210 name tc_ingress_f tag f0295cbe1ba5072a jited
```