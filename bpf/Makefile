# bpf/Makefile — compiles the TC ingress eBPF program.
#
# Produces tc_ingress.o (object) and, via bpf2go at the Go build step, the
# generated tcIngressObjects bindings used by observer_real.go.
#
# Requirements: clang (>=14), llvm, bpftool, kernel BTF (CONFIG_DEBUG_INFO_BTF=y).
#
# Run via the top-level `make build-with-ebpf` — do NOT invoke directly unless
# iterating on the C program.

CLANG     ?= clang
LLC       ?= llc
BPFTOOL   ?= bpftool
ARCH      ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KDIR      ?= /lib/modules/$$(uname -r)/build

# Generate vmlinux.h from the running kernel's BTF.
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile the TC program to a BPF object.
tc_ingress.o: tc_ingress.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	  -Wall -Werror \
	  -I. \
	  -c tc_ingress.c -o tc_ingress.o

clean:
	rm -f tc_ingress.o vmlinux.h

.PHONY: clean vmlinux.h
