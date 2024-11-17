package main

import (
	"log"
	"os"

	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const mapKey uint32 = 0

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I../../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatal("please provide a pcap file")
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

	// Open up the pcap file for reading
	handle, err := pcap.OpenOffline(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		_, _, err = objs.XdpFunc.Test(packet.Data())
		if err != nil {
			log.Fatalf("could not run the program: %s", err)
		}
		var value uint64
		if err := objs.Counter.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		// you can put a sleep here
		log.Printf("Counter %d\n", value)
	}
}
