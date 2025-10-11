package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// note that --target option used with bpf2go
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target=amd64 bpf kprobe.c -- -I../../headers -I../../vmlinux
func main() {

	// Name of the kernel function to trace.
	fn := "tcp_connect"
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

	ktc, err := link.Kprobe(fn, objs.BpfTcpConnect, nil)
	if err != nil {
		log.Fatalf("opening %s: %s", fn, err)
	}
	defer ktc.Close()

	// Handle Ctrl+C (SIGINT) to gracefully exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received
	fmt.Println("Press Ctrl+C to exit...")
	<-sigs

}
