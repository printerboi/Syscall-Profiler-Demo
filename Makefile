
bpf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	clang -O2 -g -target bpf -c syscall_trace.bpf.c -o syscall_trace.bpf.o
	bpftool gen skeleton syscall_trace.bpf.o > syscall_trace.skel.h