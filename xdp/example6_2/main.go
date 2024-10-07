package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I../../headers

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const mapKey uint32 = 0

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	redirectIfaceName := os.Args[2]
	redirectIface, err := net.InterfaceByName(redirectIfaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", redirectIfaceName, err)
	}

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

	// Before attaching the program, we need to populate the ifindex_map
	var ifIndex = uint32(redirectIface.Index)
	if err := objs.IfindexMap.Put(mapKey, &ifIndex); err != nil {
		log.Fatalf("writing the ifindex map: %v", err)
	}

	// Attach the program to the loopback interface.
	iface, _ = net.InterfaceByName(ifaceName)
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFunc,
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

	}
}
