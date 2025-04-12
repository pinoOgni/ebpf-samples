package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/unix"
)

const vethIface = "veth2"

func main() {
	filterString := "icmp" // tcpdump-style filter string

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

	// create a prio qdisc.
	// sudo ip netns exec ns2 tc qdisc add dev veth2 root handle 1: prio
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(0x0001, 0x0000),
			Parent:  tc.HandleRoot,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "prio",
			Prio: &tc.Prio{
				Bands:   3,
				PrioMap: [16]uint8{1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1}, // default values taken from florianl/go-tc examples
			},
		},
	}

	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", iface.Name, err)
		return
	}
	// when deleting the qdisc, the applied filter will also be gone
	defer tcnl.Qdisc().Delete(&qdisc)

	// cBPF filter part
	bpfByteInstructions := bpfBytes.Bytes()
	opsLen := uint16(len(bpfByteInstructions) / 8) // Each BPF instruction is 8 bytes

	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(0x1, 1), // hardcoded values for our prio qdisc
			Parent:  core.BuildHandle(0x1, 0), // hardcoded values for our prio qdisc
			Info:    0x300,                    //768 taken from florianl-tc. TODO: investigate it
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				Ops:    (*[]byte)(&bpfByteInstructions),
				OpsLen: &opsLen,
				Action: &tc.Action{
					Kind: "gact", // Generic action
					Gact: &tc.Gact{
						Parms: &tc.GactParms{
							Action: tc.ActShot, // we are dropping the packets
						},
					},
				},
			},
		},
	}

	if err = tcnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "cannot assign filter classic BPF: %v", err)
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		fmt.Println("I'm alive..")
	}
	// TODO how to exit the program and leave the qdisc created?
}
