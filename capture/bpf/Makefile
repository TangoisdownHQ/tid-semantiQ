# Build the flowmon eBPF program and its userspace loader.
#
# Requires, on the host you will run it on: clang, llvm, libbpf (headers +
# library), and bpftool. On Debian/Ubuntu:
#   sudo apt install clang llvm libbpf-dev linux-tools-common bpftool
# On Arch:
#   sudo pacman -S clang llvm libbpf bpf
#
# Targets:
#   make            build flowmon (loader) — needs root to RUN, not to build
#   make selftest   build+run the contract self-test (no kernel/root/libbpf)
#   make clean

CLANG   ?= clang
BPFTOOL ?= bpftool
CFLAGS  ?= -O2 -g -Wall
ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

.PHONY: all clean selftest
all: flowmon

# The kernel's type definitions, extracted from the running kernel's BTF.
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile the eBPF program to a BPF object.
flowmon.bpf.o: flowmon.bpf.c flowmon.h vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_$(ARCH) $(CFLAGS) \
		-I. -c flowmon.bpf.c -o $@

# Generate the libbpf skeleton the loader includes.
flowmon.skel.h: flowmon.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# The userspace loader.
flowmon: flowmon.c flowmon.skel.h flowmon.h
	$(CLANG) $(CFLAGS) -I. flowmon.c -lbpf -lelf -lz -o $@

# Contract self-test: ordinary C, no kernel/libbpf/root. This is what the
# Python test suite compiles and runs to prove the wire format matches.
selftest: selftest.c flowmon.h
	$(CLANG) $(CFLAGS) -I. selftest.c -o selftest
	./selftest

clean:
	rm -f flowmon flowmon.bpf.o flowmon.skel.h selftest vmlinux.h
