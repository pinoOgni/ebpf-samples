package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go dropicmp tc.c

const vethIface = "veth2"

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := dropicmpObjects{}
	if err := loadDropicmpObjects(&objs, nil); err != nil {
		log.Fatalf("loading drop icmp objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(vethIface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
		return
	}

	// Open a netlink/tc connection to the Linux kernel.
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	// Create and attach the qdisc/clsact to the networking interface.
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", iface.Name, err)
		return
	}
	defer tcnl.Qdisc().Delete(&qdisc)

	fd := uint32(objs.TcIngressF.FD())
	flags := uint32(0x1)

	// Create a tc/filter object to attach the eBPF program.
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
			Info:    0x300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}

	if err := tcnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not attach filter for eBPF program: %v\n", err)
		return
	}

	// Handle Ctrl+C (SIGINT) to gracefully exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Channel to signal the reading goroutine to stop
	done := make(chan struct{})

	// Start a goroutine to read from the ebpf dropped map
	go readEBPFMap(&objs, done)

	// Block until a signal is received
	fmt.Println("Press Ctrl+C to exit...")
	<-sigs

	// Signal the goroutine to stop reading
	close(done)

	// We can give the goroutine a moment to finish
	time.Sleep(100 * time.Millisecond)

}

func readEBPFMap(objs *dropicmpObjects, done chan struct{}) {
	// Periodically read the value from the counter map and log it.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			fmt.Println("Stopping reading from eBPF map.")
			return // Exit the goroutine
		case <-ticker.C:
			var value uint32
			if err := objs.DroppedMap.Lookup(uint32(0), &value); err != nil {
				log.Fatalf("reading dropped map: %v", err)
			}
			log.Printf("Counter: %d\n", value)
		}
	}
}
