#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "../.output/kb_file.skel.h"

struct kb_file_event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u8  filename[128];
    __u32 uid;
    __u32 flags;
    __u8  sensitive;
    __u64 ts_ns;
};

static volatile int running = 1;
void handle_sigint(int sig) { running = 0; }

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct kb_file_event *e = data;

    printf("[%s] PID=%-6u PPID=%-6u UID=%-5u "
           "COMM=%-16s FILE=%s\n",
           e->sensitive ? " SENSITIVE" : "FILE    ",
           e->pid, e->ppid, e->uid,
           e->comm, e->filename);

    return 0;
}

int main(void)
{
    struct kb_file_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, handle_sigint);

    printf("╔══════════════════════════════════════════╗\n");
    printf("║  KB Core — File Access Monitor           ║\n");
    printf("║  Hook 4 / Weight: 10%%                   ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    skel = kb_file_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = kb_file_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach\n");
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.kb_file_events),
        handle_event, NULL, NULL);
    if (!rb) goto cleanup;

    printf("%-13s %-6s %-6s %-5s %-16s %s\n",
           "TYPE", "PID", "PPID", "UID", "COMM", "FILE");
    printf("──────────────────────────────────────────────\n");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

cleanup:
    ring_buffer__free(rb);
    kb_file_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}