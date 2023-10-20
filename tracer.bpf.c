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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_t);
    __type(value, char *);
    __uint(max_entries, 256 * 1024);
} writes __weak SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, char[2048]);
    __uint(max_entries, 1);
} aux_maps __weak SEC(".maps");

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

// from /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
struct write_enter_ctx {
    struct trace_entry ent;
    long int id;
    long unsigned int fd;
    const char *buf;
    size_t count;
};

// from /sys/kernel/debug/tracing/events/syscalls/sys_exit_write/format
struct write_exit_ctx {
    struct trace_entry ent;
    long int id;
    long ret;
};

SEC("tp/syscalls/sys_enter_write")
int handle_write_enter(struct write_enter_ctx *ctx) {
    pid_t pid = bpf_get_current_pid_tgid();

    if (bpf_map_lookup_elem(&processes, &pid) == NULL)
        return 0;

    const char *buf = ctx->buf;
    bpf_map_update_elem(&writes, &pid, &buf, BPF_ANY);
    return 0;
}

#define MAX_WRITE_SIZE 1024

SEC("tp/syscalls/sys_exit_write")
int handle_write_exit(struct write_exit_ctx *ctx) {
    pid_t pid = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&processes, &pid) == NULL)
        return 0;

    char *buf = bpf_map_lookup_elem(&writes, &pid);
    if(buf == NULL)
        return 0;
    buf = *(char **)buf;

    bpf_map_delete_elem(&writes, &pid);

    if (ctx->ret < 0)
        return 0;

    size_t wsize = ctx->ret;
    if(wsize > MAX_WRITE_SIZE)
        wsize = MAX_WRITE_SIZE;

    u32 key = 0;
    struct write_event *e = bpf_map_lookup_elem(&aux_maps, &key);
    if(e == NULL)
        return 0;

    e->type = WRITE;
    e->proc = pid;
    e->size = wsize;
    if(bpf_probe_read_user(e->data, wsize, buf)) 
        return 0;
    bpf_ringbuf_output(&queue, e, wsize + offsetof(struct write_event, data), 0);
    return 0;
}
