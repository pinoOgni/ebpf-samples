# xdp examples

This directory is used only for xdp examples.

It is present a Makefile that can be used to generate, build or run the example.

### Table Of Contents

* [Example 1](#example-1)
* [Example 2](#example-2)
* [Example 3](#example-3)
* [Example 4](#example-4)
* [Example 5](#example-5)
* [Example 6](#example-6)
* [Example 6_2](#example-6_2)


### [Example 1](./example1/README.md)

This program basically is a xdp probe that counts the number of IPv4 packet. It checks if it is ethernet, ipv4 and not malformed. The controlplane reads the value from an array map.


### [Example 2](./example2/)

This program is similar to example 1 but designed for IPv6. To achieve this, I added a struct for the IPv6 header in the `common.h` header file, along with the value for the IPv6 protocol found within the Ethernet header.

### [Example 3](./example3/)

This program is the same as example 2 but instead of using `common.h` it uses `vmlinux.h`. 

To generate the `vmlinux.h` file you can use bpftool: `bpftool btf dump file /sys/kernel/btf/vmlinux form c >> vmlinux.h`.

### [Example 4](./example4/)

This program counts the IPv4 packets for TCP, UDP, ICMP, and Other protocols. Here *Other* refers other protocols, such as SCTP.

The map used is a hash map with 4 keys, representing the protocols: TCP, UDP, ICMP, Other.

The output will be something like that:
```
2024/10/05 11:33:21 Map contents:
        ICMP => 4
        Other => 130
        UDP => 8
```

Note: you can use iperf3 to generate SCTP traffic. Iperf3 server: `iperf3 -s` and iperf3 client `iperf3 -c 127.0.0.1 --sctp`.



### [Example 5](./example5/)

This example is the same as exanole 1 but allows the user to select an interface. So only the control plane part has changed.



### [Example 6](./example6/)

In this example I'm using the `bpf_redirect` helper to redirect traffic to another interface. To test it we can do like that:
* We create a veth pair and set both peers up:
  ```
  sudo ip link add veth0 type veth peer name veth1
  sudo ip link set dev veth0 up
  sudo ip link set dev veth1 up
  ```
* Before compiling the XDP program, we need to determine the `ifindex` of the interface to which traffic will be redirected, i.e., `loopback -> veth0 <==> veth1`. We retrieve the `ifindex` (using `ip link`) and set this value in the `xdp.c` code as the `if_index`.
* We compile the binary using the provided Makefile.
* We use the command `sudo ./example6 lo`, which attaches the XDP program to the loopback interface of the default network namespace.
* Now, if we execute `ping 127.0.0.1`, all traffic to the loopback interface will be redirected to `veth0`. We can see the redirected traffic by running tcpdump on the `veth1` peer: `sudo tcpdump -i veth1` 


Notes:
* From the `bpf_helpers` documentation on `bpf_redirect`: Currently, XDP only supports redirection to the egress interface, and accepts no flag at all. The same effect can also be attained with the more generic bpf_redirect_map(), which uses a BPF map to store the redirect target instead of providing it directly to the helper. 
* To understand why we need to use `return bpf_redirect(...)`, refer to [this documentation](https://www.kernel.org/doc/html/latest/bpf/redirect.html). Indeed if we call `bpf_redirect(...)` and then return `XDP_PASS`, it will not work as expected. Try it!
* In the next example, we will see how to retrieve the `ifindex` from a map instead of using a hardcoded value.



### [Example 6_2](./example6_2/)

6_2. This example is the same as the previous one but the ifindex is written by the controlplane in a map that will be read by the dataplane. To use it you need to run the program like that: `sudo ./example6_2 <Attach-Interface> <Redirect-Interace>`, for example `sudo ./example6_2 lo veth0`, the program will be attached to the loopback interface and the traffic will be redirect to the veth0 interface.

We can check the content of the BPF map `ifindex_map` using bpftool:
```
sudo bpftool map show
...
47: array  name ifindex_map  flags 0x0
	key 4B  value 4B  max_entries 1  memlock 328B
```
Then:
```
sudo bpftool map dump id 47
key: 00 00 00 00  value: 09 00 00 00
```
We can check that the value is present as ifindex with:
```
ip link
...
8: veth1@veth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 16:dd:a3:97:f1:bd brd ff:ff:ff:ff:ff:ff
9: veth0@veth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 7a:a1:2c:6e:67:67 brd ff:ff:ff:ff:ff:ff
```