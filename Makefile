ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

all: exec

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# kernel half -> BPF object. -g is REQUIRED (embeds BTF for CO-RE); -O2 REQUIRED.
# -D__TARGET_ARCH_x86 isn't used by this program but you'll need it for kprobes later.
exec.bpf.o: exec.bpf.c vmlinux.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c exec.bpf.c -o exec.bpf.o

# userspace half -> ordinary binary, linked against libbpf (+ libelf + zlib, its deps)
exec: exec.c exec.bpf.o
	clang -g -O2 -Wall exec.c -lbpf -lelf -lz -o exec

clean:
	rm -f exec exec.bpf.o

.PHONY: all clean