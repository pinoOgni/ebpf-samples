package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I../../headers

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"
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

	// Retrieve all network interfaces
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("Failed to retrieve interfaces: %v", err)
	}
	for _, l := range links {
		if isEligible(l) {
			key := uint32(l.Attrs().Index)
			if err := objs.bpfMaps.IfCounterMap.Put(&key, uint64(0)); err != nil {
				log.Fatalf("error setting if index counter map %v", err)
			}
		}
	}

	for _, l := range links {
		// Check if in the interface is there any xdp program already attached and it's loopback/veth
		if isEligible(l) {
			fmt.Printf("Name: %s, Index: %d, Type: %s\n", l.Attrs().Name, l.Attrs().Index, l.Type())
			iface, _ := net.InterfaceByName(l.Attrs().Name)
			la, err := link.AttachXDP(link.XDPOptions{
				Program:   objs.XdpFunc,
				Interface: iface.Index,
			})
			if err != nil {
				log.Fatalf("could not attach XDP program %s", err)
			}
			defer la.Close()
		}
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		var value uint64
		if err := objs.Counter.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("Counter map %d\n", value)

		s, err := formatMapContents(objs.IfCounterMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Interface map:\n%s", s)
	}

}

// isEligible checks if it is possible to attach the program to an interface
// to be eligible an interface doesn't have already a xdp program AND
// it has to be a loopback up interface OR
// a veth up
func isEligible(l netlink.Link) bool {
	return !l.Attrs().Xdp.Attached &&
		((l.Attrs().Flags == net.FlagLoopback|net.FlagUp) ||
			(l.Attrs().OperState == netlink.OperUp && l.Type() == "veth"))
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key uint32
		val uint64
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		interfaceName, _ := net.InterfaceByIndex(int(key))
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", interfaceName.Name, val))
	}
	return sb.String(), iter.Err()
}
