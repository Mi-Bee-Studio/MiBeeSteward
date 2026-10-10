# bpf/Makefile — compiles the TC ingress eBPF program.
#
# Produces tc_ingress.o (object) for manual iteration; the Go build path uses
# bpf2go (go generate ./internal/service/scannerv2/ebpf/) which invokes clang
# itself and embeds the object into the binary.
#
# Requirements: clang (>=14) ONLY — any host OS. The program is CO-RE free
# (UAPI types only, see bpf_standalone.h): no bpftool, no kernel BTF, no
# libbpf headers, no Linux headers.
#
# Run via the top-level `make build-with-ebpf` — do NOT invoke directly unless
# iterating on the C program.

CLANG ?= clang

tc_ingress.o: tc_ingress.c bpf_standalone.h
	$(CLANG) -g -O2 -target bpf \
	  -Wall -Werror \
	  -I. \
	  -c tc_ingress.c -o tc_ingress.o

clean:
	rm -f tc_ingress.o

.PHONY: clean
