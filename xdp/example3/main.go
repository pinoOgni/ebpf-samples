package main

// This program simply attach a ebpf program to xdp, in particular to the
// loopback interface and count the Ipv4 packet
// The controlplane see the number of packet reading a map

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I../../headers -I../../vmlinux

import (
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const mapKey uint32 = 0

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading object %v", err)
	}
	defer objs.Close()

	// Attach the program to the loopback interface.
	iface, _ := net.InterfaceByName("lo")
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFunction,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program %s", err)
	}
	defer l.Close()

	// Periodically read the value from the counter map and log it.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		var value uint32
		if err := objs.Counter.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("Counter %d\n", value)
	}
}
