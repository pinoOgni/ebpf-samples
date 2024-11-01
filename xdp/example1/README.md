# XDP example 1

## Controlplane

1. It sets a constant `mapKey` to `0`.
2. It allows the current process to lock memory for eBPF resources.
3. It loads pre-compiled programs and maps into the kernel.
4. It attaches the XDP (eXpress Data Path) program to the loopback interface.
5. It creates a ticker that ticks every second.
6. It enters a loop where, on each tick of the ticker:
   - It reads the value associated with `mapKey` from the counter map.
   - It logs the value of the counter.

## Dataplane

In this first example I would like to add some more comments:

1. `void *data_end = (void*)(long)ctx->data_end;`:
   - This line initializes a pointer `data_end` to the end of the packet data. It's casting `ctx->data_end` to a `long` and then casting it again to a `void *`.
   - `ctx->data_end` is a field in the `struct xdp_md` structure which represents the end of the packet data.

2. `void *data = (void*)(long)ctx->data;`:
   - This line initializes a pointer `data` to the start of the packet data. Similar to `data_end`, it's casting `ctx->data` to a `long` and then casting it again to a `void *`.
   - `ctx->data` is a field in the `struct xdp_md` structure which represents the start of the packet data.

3. `struct ethhdr *eth = data;`:
   - This line declares a pointer `eth` of type `struct ethhdr` and initializes it with the address of the packet data.
   - `struct ethhdr` is a structure representing the Ethernet header.

4. `if ((void *)(eth + 1) > data_end) { return 0; }`:
   - This condition checks if the Ethernet header extends beyond the end of the packet data.
   - `(eth + 1)` calculates the address of the next memory location after the Ethernet header.
   - `(eth + 1 > data_end)` checks if this calculated address is greater than `data_end`, meaning it's beyond the end of the packet.
   - If the condition is true, it means the Ethernet header extends beyond the packet data, indicating a malformed packet, so it returns `0` to indicate failure.

5. `struct iphdr *ip = (void *)(eth + 1);`:
   - This line declares a pointer `ip` of type `struct iphdr` and initializes it with the address of the memory location immediately after the Ethernet header.
   - `struct iphdr` is a structure representing the IP header.

6. `if ((void *)(ip + 1) > data_end) { return 0; }`:
   - This condition checks if the IP header extends beyond the end of the packet data.
   - `(ip + 1)` calculates the address of the next memory location after the IP header.
   - `(ip + 1) > data_end)` checks if this calculated address is greater than `data_end`, meaning it's beyond the end of the packet.
   - If the condition is true, it means the IP header extends beyond the packet data, indicating a malformed packet, so it returns `0` to indicate failure.

