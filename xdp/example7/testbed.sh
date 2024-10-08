#!/bin/bash


sudo ip netns add ns1

sudo ip link add veth1 type veth peer name veth2
sudo ip link add veth3 type veth peer name veth4

sudo ip link set veth2 netns ns1
sudo ip link set veth4 netns ns1

sudo ip link set dev veth1 up
sudo ip link set dev veth3 up

sudo ip netns exec ns1 ip link set dev veth2 up
sudo ip netns exec ns1 ip link set dev veth4 up

sudo ip netns exec ns1 ip link set dev lo up

sudo ip addr add 10.0.0.1/30 dev veth1
sudo ip addr add 10.0.1.1/30 dev veth3

sudo ip netns exec ns1 ip addr add 10.0.0.2/30 dev veth2
sudo ip netns exec ns1 ip addr add 10.0.1.2/30 dev veth4

