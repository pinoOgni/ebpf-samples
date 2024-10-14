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

func clearTerminal() {
	// ANSI escape code to clear the screen
	fmt.Print("\033[H\033[2J")
}

const maxFilenameLen = 256

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

	// Open a tracepoint and attach the pre-compiled program to the sys_enter_execve
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.CountExecve, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	// Periodically read the value from the counter map and log it.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Create a buffer to hold the key (binary name)
	key := make([]byte, maxFilenameLen)
	value := uint64(0)

	for range ticker.C {
		// Clear the terminal before printing the new data
		//clearTerminal()

		// Iterate through the map using a MapIterator
		iter := objs.ExecCountMap.Iterate()

		for iter.Next(&key, &value) {
			fmt.Printf("Binary: %s, Count: %d\n", string(key[:]), value)
		}

		if err := iter.Err(); err != nil {
			log.Fatalf("failed to iterate over map: %v", err)
		}
	}
}
