# xdp examples

This directory is used only for xdp examples.

It is present a Makefile that can be used to generate, build or run the example.


### [Example 1](./example1/README.md)

Notes:
* This program basically is a xdp probe that counts the number of IPv4 packet. 
* It checks if it is ethernet, ipv4 and not malformed. 
* The controlplane reads the value from an array map.
