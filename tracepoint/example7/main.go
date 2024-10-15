package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tracepoint.c -- -I../../headers

const mapKey uint32 = 0

// getPIDByName retrieves the PID of the first process with the given name
func getPIDByName(name string) (uint32, error) {
	// Execute the `pgrep` command to find the PID of the process by name
	cmd := exec.Command("pgrep", "-n", name) // `-n` gets the most recent matching process
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("could not find process: %w", err)
	}

	// Convert the output to a string, trim any spaces/newlines, and parse the PID
	pidStr := strings.TrimSpace(out.String())
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid PID: %w", err)
	}

	return uint32(pid), nil
}

// Get the PID of the process by name (replace "icmp_sender" with your target process)
var processName = "icmp_sender"

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

	// Open a tracepoint and attach the pre-compiled program for the netif_rx
	netifRx, err := link.Tracepoint("net", "netif_rx", objs.CountNetifRx, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer netifRx.Close()
	// Open a tracepoint and attach the pre-compiled program for the net_dev_xmit
	netDevXmit, err := link.Tracepoint("net", "net_dev_xmit", objs.CountNetifXmit, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer netDevXmit.Close()

	pid, err := getPIDByName(processName)
	if err != nil {
		log.Fatalf("could not retrieve PID for process %s: %v", processName, err)
	}
	fmt.Printf("Found PID for process %s: %d\n", processName, pid)

	// Populate the pid_map with the found PID
	var valuePid uint32 = pid
	if err := objs.PidMap.Put(mapKey, &valuePid); err != nil {
		log.Fatalf("writing the pid map: %v", err)
	}
	var getValuePid uint32
	if err := objs.PidMap.Lookup(mapKey, &getValuePid); err != nil {
		log.Fatalf("reading map: %v", err)
	}
	fmt.Println("valuepid ", getValuePid)

	// Get the number of available CPUs
	numCPUs := runtime.NumCPU()
	zeros := make([]uint64, numCPUs)
	// we need to put 0 values in the map otherwise if it's empty we will
	// get an error
	// sent packets --> key: 0
	if err := objs.PacketCountMap.Put(uint32(0), zeros); err != nil {
		log.Fatalf("writing the packet_count_map map: %v", err)
	}
	// received packets --> key: 1
	if err := objs.PacketCountMap.Put(uint32(1), zeros); err != nil {
		log.Fatalf("writing the packet_count_map map: %v", err)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var sent, received []uint64
	var sentSum, receivedSum uint64
	for range ticker.C {
		// Reset sums to 0 at the start of each iteration
		sentSum = 0
		receivedSum = 0
		if err := objs.PacketCountMap.Lookup(uint32(0), &sent); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		if err := objs.PacketCountMap.Lookup(uint32(1), &received); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		for _, v := range sent {
			sentSum += v
		}
		for _, v := range received {
			receivedSum += v
		}
		fmt.Printf("Sent packets %d\n", sentSum)
		fmt.Printf("Received packets %d\n", receivedSum)
	}
}
