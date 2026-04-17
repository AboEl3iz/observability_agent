package main

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type ProcKey struct {
	PID  uint32
	TID  uint32
	Comm [16]byte
}

func main() {
	spec, err := ebpf.LoadCollectionSpec("ebpf/program.o")
	if err != nil {
		log.Fatal(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()

	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", coll.Programs["trace_execve"], nil)
	if err != nil {
		log.Fatalf("attaching trace_execve: %s", err)
	}
	defer tpExecve.Close()

	tpSched, err := link.Tracepoint("sched", "sched_switch", coll.Programs["trace_sched"], nil)
	if err != nil {
		log.Fatalf("attaching trace_sched: %s", err)
	}
	defer tpSched.Close()

	tpNet, err := link.Tracepoint("net", "netif_receive_skb", coll.Programs["trace_netif_receive"], nil)
	if err != nil {
		log.Fatalf("attaching trace_netif_receive: %s", err)
	}
	defer tpNet.Close()

	syscallMap := coll.Maps["syscall_count"]
	ctxMap := coll.Maps["ctx_switch_count"]
	packetMap := coll.Maps["packet_count"]

	var key uint32 = 0
	var prevCtx uint64
	var prevPacket uint64

	for {
		time.Sleep(1 * time.Second)

		var ctxCount uint64
		ctxMap.Lookup(&key, &ctxCount)

		var packetCount uint64
		packetMap.Lookup(&key, &packetCount)

		fmt.Printf("\n--- Stats ---\n")
		fmt.Printf("Context Switch/sec: %d | Packets/sec: %d\n", ctxCount-prevCtx, packetCount-prevPacket)
		prevCtx = ctxCount
		prevPacket = packetCount

		fmt.Println("---- Execve Syscalls ----")

		iter := syscallMap.Iterate()
		var procKey ProcKey
		var count uint64

		for iter.Next(&procKey, &count) {
			comm := string(bytes.TrimRight(procKey.Comm[:], "\x00"))
			fmt.Printf("Process: %s (PID: %d, TID: %d) -> %d execves\n", comm, procKey.PID, procKey.TID, count)
		}
	}
}