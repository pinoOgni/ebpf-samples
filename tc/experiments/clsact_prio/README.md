# clsact and prio qdiscs

In this example, I wanted to try attaching an eBPF program to the egress path using a clsact qdisc, and a cBPF program (filter with action) using a prio qdisc, which, as far as I understand, is only for egress.

Basically, I was studying TC (and I'm studying also right now for sure) and came across the dilemma: "Can multiple qdiscs be used together? If so, how?" I found some examples where multiple `netem` qdiscs were added directly from the terminal but I was looking for something else. So, I decided to use some existing prvious examples and mix them.

I found that it's possible to add a `clsact` qdisc (which works for both `ingress` and `egress`) and a `prio` qdisc, which apparently is only for `egress`.

Long story short:

* The `clsact` program is an existing TC example (in tc directory) that creates a clsact `qdisc` and then attaches an eBPF program that drops ICMP packets and saves a counter in a map.
* The `prio` program is a slightly modified existing TC example (in tc directory) that creates a prio `qdisc` and then attaches a cBPF filter (written in tcpdump style) that drops ICMP packets.

From the tests I've done, I observed that the `clsact` program could see and drop ICMP packets even when the `prio` program's filter was active, and I couldn't see any ICMP echo reply packets from `ping` command. From this, I concluded that, at least with the parameters I used to create the `qdiscs` and filters, the eBPF program in the `clsact` qdisc has priority over the cBPF filter in the `prio` qdisc. For sure I will do other tests and study that because it seems interesting.

To test it, I did this:

1. build the `clsact` 
```
cd clsact
go generate .
go build -a -o bin/ .
```
2. build the `prio`
```
go build -a -o bin/ .
```

3. create the usual testbed
```
sudo ip link add name veth1 type veth peer name veth2
sudo ip netns add ns2
sudo ip link set veth2 netns ns2
sudo ip netns exec ns2 ip link set dev veth2 up
sudo ip link set veth1 up
sudo ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2
sudo ip addr add 10.0.0.1/24 dev veth1
```
4. Check the connection:
```
# in one terminal
ping 10.0.0.2

# in another terminal
sudo ip netns exec ns2 tcpdump -i veth2 -vvv
```
5. Run the `clsact` program alone. We can see the icmp echo requests on `veth2` but we can't see the icmp echo replies and also we can see the incremented counter of dropped icmp packets:
```
sudo ip netns exec ns2 ./bin/clsact
```
6. Run the `prio` program alone. We should have the same result.
```
sudo ip netns exec ns2 ./bin/clsact

# note: to remove the prio qdisc we can use this command
# sudo ip netns exec ns2 ./bin/clsact
```
7. Now we can run both and see that the `clsact` is still dropping packets. If we stop it and we leave the `prio` running the result does not change.



Notes: we can check the qdiscs and cBPF filter attached to `veth2`:
```
sudo ip netns exec ns2 tc qdisc show dev veth2

sudo ip netns exec ns2 tc filter show dev veth2
```
And also the tc eBPF program with `bpftool`: `sudo bpftool prog show`.