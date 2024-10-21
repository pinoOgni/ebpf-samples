package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/unix"
)

const vethIface = "veth1"

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
	bpfByteInstructions := bpfBytes.Bytes()
	opsLen := uint16(len(bpfByteInstructions) / 8) // Each BPF instruction is 8 bytes

	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(0xffff, 1),
			Parent:  core.BuildHandle(0xffff, 0),
			Info:    0x300, //768 taken form florianl-tc. TODO: investigate it
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
							Action: tc.ActShot,
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
}
