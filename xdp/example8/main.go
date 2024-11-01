package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I../../headers

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var addr = ":9091"

const mapKey uint32 = 0

var interface_map map[int]string

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

	interface_map = make(map[int]string)
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
			interface_map[l.Attrs().Index] = l.Attrs().Name
			var key = uint32(l.Attrs().Index)
			var initValue uint64 = 0
			if err := objs.IfCounterMap.Put(&key, &initValue); err != nil {
				log.Fatal("error while setting interface counter map ", err)
			}
			// The defer is called after main is closed
			defer la.Close()
		}
	}

	// Prometheus http handler
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Fatal(http.ListenAndServe(addr, nil))
	}()

	// Prometheus metrics
	// Let's create a simple metric counter (value that can be only incremented)
	ipv4_packets_total := promauto.NewCounter(prometheus.CounterOpts{
		Name: "ipv4_packets_total",
		Help: "Total number of IPv4 packets received in ingress using XDP program",
	})
	// Now let's create a metric gauge (value that can be up and down)
	packet_received := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "packet_received",
		Help: "Number of IPv4 packets currently received in ingress by an interface using XDP program",
	}, []string{"interface"})

	// Usual loop
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		var counter uint64
		var gauge uint64
		if err := objs.Counter.Lookup(mapKey, &counter); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("Counter eBPF map %d\n", counter)

		s, err := formatMapContents(objs.IfCounterMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Interface map:\n%s", s)

		// prometheus metrics
		ipv4_packets_total.Add(float64(counter))

		for k, v := range interface_map {
			metric, err := packet_received.GetMetricWithLabelValues(v)
			if err != nil {
				log.Fatal("metric with given label not found", err)
			}
			if err := objs.IfCounterMap.Lookup(uint32(k), &gauge); err != nil {
				log.Fatalf("reading interface map while setting packet_received_per_interface metric: %v", err)
			}
			metric.Set(float64(gauge))
		}
	}

}

// isEligible checks if it is possible to attach the program to an interface
// to be eligible an interface doesn't have already a xdp program AND
// it has to be a loopback up interface OR a veth up
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
