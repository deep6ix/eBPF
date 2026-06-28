package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// MUST match struct event in exec.bpf.c byte-for-byte.
type event struct {
	Pid      uint32
	Ppid     uint32
	Comm     [16]uint8
	Filename [256]uint8
}

func gostr(b []uint8) string {
	if i := bytes.IndexByte(b, 0); i != -1 {
		return string(b[:i])
	}
	return string(b)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("exec.bpf.o")
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("verifier rejected program:\n%+v", ve)
		}
		log.Fatalf("new collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["handle_execve"]
	if prog == nil {
		log.Fatal("program handle_execve not found")
	}

	// Grab the ring buffer map by its C name and open a reader on it.
	rb := coll.Maps["events"]
	if rb == nil {
		log.Fatal("map events not found")
	}
	rd, err := ringbuf.NewReader(rb)
	if err != nil {
		log.Fatalf("open ringbuf reader: %v", err)
	}
	defer rd.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	defer tp.Close()

	// Read() blocks. Closing the reader from the signal handler makes it
	// return ErrClosed so the loop — and the program — can exit cleanly.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		rd.Close()
	}()

	log.Println("listening for execve... Ctrl-C to stop.")
	log.Printf("%-8s %-8s %-16s %s", "PID", "PPID", "COMM", "FILENAME")

	var e event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("reading ringbuf: %v", err)
			continue
		}

		// Decode raw bytes into our struct. NativeEndian because the kernel
		// wrote them in host byte order.
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &e); err != nil {
			log.Printf("decode: %v", err)
			continue
		}

		log.Printf("%-8d %-8d %-16s %s",
			e.Pid, e.Ppid, gostr(e.Comm[:]), gostr(e.Filename[:]))
	}
}
