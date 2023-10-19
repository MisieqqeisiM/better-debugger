#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} queue __weak SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_t);
    __type(value, int);
    __uint(max_entries, 256 * 1024);
} processes __weak SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    pid_t old = ctx->old_pid;
    pid_t new = ctx->pid;
    int value = 0;

    if(bpf_map_lookup_elem(&processes, &old) != NULL) {
        bpf_map_delete_elem(&processes, &old);
        bpf_map_update_elem(&processes, &new, &value, BPF_ANY);
        bpf_ringbuf_output(&queue, &new, sizeof(new), 0);
    }
    return 0;
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    pid_t parent = ctx->parent_pid;
    pid_t child = ctx->child_pid;
    int value = 0;

    if(bpf_map_lookup_elem(&processes, &parent) != NULL) {
        struct task_struct *task = (void *)bpf_get_current_task();
        bpf_map_update_elem(&processes, &child, &value, BPF_ANY);
    }
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    pid_t pid = ctx->pid;
    if(bpf_map_lookup_elem(&processes, &pid) != NULL) {
        bpf_printk("%d", pid);
    }
    bpf_map_delete_elem(&processes, &pid);
    return 0;
}