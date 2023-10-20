#pragma once 

enum event_type {
    FORK,
    EXIT,
    EXEC,
    WRITE
};

struct fork_event {
    enum event_type type;
    pid_t parent;
    pid_t child;
};

struct exec_event {
    enum event_type type;
    pid_t proc;
};

struct exit_event {
    enum event_type type;
    pid_t proc;
};

struct write_event {
    enum event_type type;
    pid_t proc;
    int size;
    char data[];
};

union event {
    enum event_type type;
    struct fork_event fork;
    struct exec_event exec;
    struct exit_event exit;
    struct write_event write;
};

inline void make_fork_event(struct fork_event *event, pid_t parent, pid_t child) {
    event->type = FORK;
    event->parent = parent;
    event->child = child;
}

inline void make_exit_event(struct exit_event *event, pid_t proc) {
    event->type = EXIT;
    event->proc = proc;
}

inline void make_exec_event(struct exec_event *event, pid_t proc) {
    event->type = EXEC;
    event->proc = proc;
}