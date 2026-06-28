ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
CLANG := clang
VMLINUX_DIR := bpf
INCLUDES := -I$(VMLINUX_DIR)

CFLAGS := -g -O2 -Wall -Wno-missing-declarations
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH)

exec.bpf.o: bpf/exec.bpf.c
	$(CLANG) $(CFLAGS) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f exec.bpf.o exec-tracer

.PHONY: clean