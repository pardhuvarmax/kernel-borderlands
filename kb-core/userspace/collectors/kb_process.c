#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "../.output/kb_process.skel.h"

struct kb_process_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u8  comm[16];
    __u8  filename[64];
    __u8  event_type;
    __u64 ts_ns;
};

static volatile int running = 1;

void handle_sigint(int sig) { running = 0; }

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct kb_process_event *e = data;
    const char *type;

    switch (e->event_type) {
        case 0: type = "EXEC"; break;
        case 1: type = "EXIT"; break;
        case 2: type = "FORK"; break;
        default: type = "UNKNOWN";
    }

    printf("[KB] %-6s | PID=%-6u PPID=%-6u UID=%-5u COMM=%-16s\n",
           type, e->pid, e->ppid, e->uid, e->comm);

    return 0;
}

int main(void)
{
    struct kb_process_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, handle_sigint);

    printf("╔══════════════════════════════════════╗\n");
    printf("║  KB Core — Process Lineage Tracker   ║\n");
    printf("║  Kernel Borderlands v0.1             ║\n");
    printf("╚══════════════════════════════════════╝\n\n");

    skel = kb_process_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = kb_process_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.kb_events),
        handle_event, NULL, NULL
    );
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("%-6s | %-6s %-6s %-5s %-16s\n",
           "TYPE", "PID", "PPID", "UID", "COMM");
    printf("─────────────────────────────────────\n");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

cleanup:
    ring_buffer__free(rb);
    kb_process_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}