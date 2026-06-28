package main

import (
	"errors"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Lift RLIMIT_MEMLOCK — only needed on kernels < 5.11, harmless after.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock: %v", err)
	}

	// 1. OPEN — parse the .o into an in-memory spec. Nothing in the kernel yet.
	//    (C: bpf_object__open_file)
	spec, err := ebpf.LoadCollectionSpec("exec.bpf.o")
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}

	// 2. LOAD — verifier runs here; programs + maps installed into the kernel.
	//    (C: bpf_object__load)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// Print the FULL verifier log on rejection — the Go analog of the
		// libbpf print callback. Without %+v you get a truncated one-liner.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("verifier rejected program:\n%+v", ve)
		}
		log.Fatalf("new collection: %v", err)
	}
	defer coll.Close()

	// 3. find the program by its C function name.
	//    (C: bpf_object__find_program_by_name)
	prog := coll.Programs["handle_execve"]
	if prog == nil {
		log.Fatal("program handle_execve not found in object")
	}

	// 4. ATTACH — wire it onto tracepoint syscalls:sys_enter_execve.
	//    (C: bpf_program__attach)
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("attached. in another terminal: sudo cat /sys/kernel/tracing/trace_pipe")
	log.Println("Ctrl-C to detach.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}
