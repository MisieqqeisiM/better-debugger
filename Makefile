all: vmlinux.h
	@clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c tracer.bpf.c -o tracer.bpf.o
	@bpftool gen skeleton tracer.bpf.o name tracer > tracer.skel.h
	@clang++ -std=c++20 tracer.cpp -lbpf -lelf -o tracer

vmlinux.h:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean
clean:
	@rm tracer.skel.h vmlinux.h tracer *.o