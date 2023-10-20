#include <sys/resource.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include <exception>
#include <string>
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
        case WRITE:
            std::cout << "write " << e->write.proc << ": \"";
            for(int i = 0; i < e->write.size; i++) {
                char c = e->write.data[i];
                if(c == '\n')
                    std::cout << "\\n";
                else if(c == '\t')
                    std::cout << "\\t";
                else
                    std::cout << c;
            }
            std::cout << "\"";
            std::cout << std::endl;
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

    int value = 0;

    pid_t child = fork();

    if(child == 0) {
        pid_t pid = getpid();
        bpf_map__update_elem(skel->maps.processes, &pid, sizeof(pid), &value, sizeof(value), BPF_ANY);
        execvp(argv[1], argv + 1);
        exit(-1);
    }


    while(has_children())
        ring_buffer__consume(buffer);
    ring_buffer__consume(buffer);

    tracer::detach(skel);
    tracer::destroy(skel);
    return 0;
}