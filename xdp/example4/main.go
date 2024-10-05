package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I../../headers


import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading object %v", err)
	}
	defer objs.Close()

	iface, _ := net.InterfaceByName("lo")
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFunction,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatalf("could not attach XDP program %s", err)
	}
	defer l.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(objs.Counter)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}


func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key uint32
		val uint32
	)
	iter := m.Iterate()
	var protocol string
	for iter.Next(&key, &val) {
		switch key {
		case 1:
			protocol = "ICMP"
		case 6:
			protocol = "TCP"
		case 17: 
			protocol = "UDP"
		default:
			protocol = "Other"
		}
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", protocol, val))
	}
	return sb.String(), iter.Err()
}