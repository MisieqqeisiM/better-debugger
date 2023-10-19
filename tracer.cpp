#include <sys/resource.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include <exception>
#include <iostream>

#include "tracer.skel.h"
#include "event.h"

static int buf_process_sample(void *ctx, void *data, size_t len) {
    event *e = (event *)data;
    switch (e->type)
    {
        case FORK:
            std::cout << "fork " << e->fork.parent << "->" << e->fork.child << std::endl;
        break;
        case EXIT:
            std::cout << "exit " << e->exit.proc << std::endl;
        break;
        case EXEC:
            std::cout << "exec " << e->exec.proc << std::endl;
        break;
    }
    
    return 0;
}

bool has_children() {
    pid_t err;
    while((err = waitpid(-1, nullptr, WNOHANG)) > 0);
    return err == 0;
}

int main(int argc, char * argv[]) {
    prctl(PR_SET_CHILD_SUBREAPER);
    rlimit lim {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if(setrlimit(RLIMIT_MEMLOCK, &lim))
        throw "Failed to increase RLIMIT_MEMLOCK\n";

    auto *skel = tracer::open_and_load();
    tracer::attach(skel);

    auto buffer = ring_buffer__new(bpf_map__fd(skel->maps.queue), buf_process_sample, nullptr, nullptr);

    pid_t pid = getpid();
    int value = 0;
    bpf_map__update_elem(skel->maps.processes, &pid, sizeof(pid), &value, sizeof(value), BPF_ANY);

    pid_t child = fork();

    if(child == 0) {
        execvp(argv[1], argv + 1);
        exit(-1);
    }

    while(has_children()) {
        ring_buffer__consume(buffer);
    }

    tracer::detach(skel);
    tracer::destroy(skel);
    return 0;
}