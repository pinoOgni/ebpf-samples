// This program demonstrates attaching an eBPF program to a kernel tracepoint.
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tracepoint.c -- -I../../headers

const mapKey uint32 = 0

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

	// Open a tracepoint and attach the pre-compiled program for the tpKmalloc
	tpKmalloc, err := link.Tracepoint("kmem", "kmalloc", objs.TrackKmalloc, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tpKmalloc.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var allocatedByte uint64
	for range ticker.C {
		if err := objs.MemoryMap.Lookup(mapKey, &allocatedByte); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		fmt.Printf("Allocated bytes: %d\n", allocatedByte)
	}
}
