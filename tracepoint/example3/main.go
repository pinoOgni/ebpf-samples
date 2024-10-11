// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The idea and the C code is taken from https://blog.tofile.dev/2021/08/01/bad-bpf.html
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tracepoint.c -- -I../../headers

// Define the keys for incoming and outgoing packet counters.
const (
	INCOMING = 1
	OUTGOING = 2
)

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
	sendTp, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.BpfProgSendto, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer sendTp.Close()

	// Open a tracepoint and attach the pre-compiled program.
	recvTp, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.BpfProgRecvfrom, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer recvTp.Close()

	// Periodically read and print the incoming and outgoing packet counters.
	var incomingCount, outgoingCount uint64
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := objs.PacketCounters.Lookup(uint32(INCOMING), &incomingCount); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		if err := objs.PacketCounters.Lookup(uint32(OUTGOING), &outgoingCount); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		fmt.Printf("Incoming packets: %d\n", incomingCount)
		fmt.Printf("Outgoing packets: %d\n", outgoingCount)

	}

}
