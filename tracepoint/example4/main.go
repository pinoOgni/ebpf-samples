// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The idea and the C code is taken from https://blog.tofile.dev/2021/08/01/bad-bpf.html
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tracepoint.c -- -I../../headers

func clearTerminal() {
	// ANSI escape code to clear the screen
	fmt.Print("\033[H\033[2J")
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a tracepoint and attach the pre-compiled program for the sendto
	sendTp, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.CountPacketsByDest, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer sendTp.Close()

	// Periodically read and print the incoming packet counters.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Clear the terminal before printing the new data
		clearTerminal()

		// Iterate through the map using a MapIterator
		iter := objs.PacketCountMap.Iterate()
		var ipKey uint32
		var count uint64
		for iter.Next(&ipKey, &count) {
			// Convert the IP from network byte order to human-readable format
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, ipKey)
			fmt.Printf("IP: %s, Packets: %d\n", ip.String(), count)
		}

		// Check for iteration errors
		if err := iter.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error during iteration: %v\n", err)
			os.Exit(1)
		}
	}
}
