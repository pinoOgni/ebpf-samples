package main

import (
	"bytes"
	"encoding/binary"
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
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go count tc.c

const vethIface = "veth2"

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := countObjects{}
	if err := loadCountObjects(&objs, nil); err != nil {
		log.Fatalf("loading count objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(vethIface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
		return
	}

	// =========================== clsact ===========================================
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

	// =========================== eBPF count program ===========================================
	fd := uint32(objs.TcIngressF.FD())
	flags := uint32(0x1)

	// Create a tc/filter object to attach the eBPF program.
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  1,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
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

	// =========================== cBPF program ===========================================
	//filterString := "icmp[icmptype] == icmp-echoreply" // tcpdump-style filter string
	filterString := "icmp[icmptype] == icmp-echo && src host 10.0.0.1" // tcpdump-style filter string

	// Compile the filter string to BPF
	bpfInstructions, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, filterString)
	if err != nil {
		log.Fatalf("Error compiling filter: %v", err)
	}

	// Convert BPF instructions to []byte
	var bpfBytes bytes.Buffer
	for _, ins := range bpfInstructions {
		if err := binary.Write(&bpfBytes, binary.LittleEndian, ins); err != nil {
			log.Fatalf("Error converting BPF instruction to bytes: %v", err)
		}
	}

	// Adding the cBPF filter: I just set the Handle and that's all.
	// About the priority, the second filter it will have a pref (priority) with a lower number, i.e. higher priority
	// TODO: I don't understand why the Action here is not working. The filter yes, the action no.
	ops2 := bpfBytes.Bytes()
	opsLen2 := uint16(len(ops2) / 8) // Each BPF instruction is 8 bytes

	// TODO: understand bettere class and flags
	classID2 := uint32(0x1001)
	flags2 := uint32(0x1)

	filter2 := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  2,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    0x300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				Ops:     &ops2,
				OpsLen:  &opsLen2,
				ClassID: &classID2,
				Flags:   &flags2,
				// Action: &tc.Action{
				// 	Kind: "gact", // Generic action
				// 	Gact: &tc.Gact{
				// 		Parms: &tc.GactParms{
				// 			Action: tc.ActShot,
				// 		},
				// 	},
				// },
			},
		},
	}
	if err := tcnl.Filter().Add(&filter2); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign cBPF: %v\n", err)
		return
	}

	// ================= signal management ============================
	// Handle Ctrl+C (SIGINT) to gracefully exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Channel to signal the reading goroutine to stop
	done := make(chan struct{})

	// Start a goroutine to read from the ebpf counter map
	go readEBPFMap(&objs, done)

	// Block until a signal is received
	fmt.Println("Press Ctrl+C to exit...")
	<-sigs

	// Signal the goroutine to stop reading
	close(done)

	// We can give the goroutine a moment to finish
	time.Sleep(100 * time.Millisecond)

}

func readEBPFMap(objs *countObjects, done chan struct{}) {
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
			if err := objs.CounterMap.Lookup(uint32(0), &value); err != nil {
				log.Fatalf("reading counter map: %v", err)
			}
			log.Printf("Counter: %d\n", value)
		}
	}
}
