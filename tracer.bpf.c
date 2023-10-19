#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

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
        struct exec_event *event = bpf_ringbuf_reserve(&queue, sizeof(struct exec_event), 0);
        if(event == NULL)
            return 0;
        make_exec_event(event, new);
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    pid_t parent = ctx->parent_pid;
    pid_t child = ctx->child_pid;
    int value = 0;

    if(bpf_map_lookup_elem(&processes, &parent) != NULL) {
        bpf_map_update_elem(&processes, &child, &value, BPF_ANY);
        struct fork_event *event = bpf_ringbuf_reserve(&queue, sizeof(struct fork_event), 0);
        if(event == NULL)
            return 0;
        make_fork_event(event, parent, child);
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    pid_t pid = ctx->pid;
    if(bpf_map_lookup_elem(&processes, &pid) != NULL) {
        struct exit_event *event = bpf_ringbuf_reserve(&queue, sizeof(struct exit_event), 0);
        if(event == NULL)
            return 0;
        make_exit_event(event, pid);
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&processes, &pid);
    return 0;
}