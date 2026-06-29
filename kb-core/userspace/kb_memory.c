#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "../.output/kb_memory.skel.h"

struct kb_memory_event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u32 uid;
    __u64 addr;
    __u64 length;
    __u32 prot;
    __u32 flags;
    __u8  event_type;
    __u8  rwx;
    __u8  anonymous;
    __u64 ts_ns;
};

static volatile int running = 1;
void handle_sigint(int sig) { running = 0; }

static void prot_str(__u32 prot, char *buf)
{
    buf[0] = (prot & 1) ? 'R' : '-';
    buf[1] = (prot & 2) ? 'W' : '-';
    buf[2] = (prot & 4) ? 'X' : '-';
    buf[3] = '\0';
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct kb_memory_event *e = data;
    char prot[4];
    prot_str(e->prot, prot);

    printf("[%s] PID=%-6u PPID=%-6u COMM=%-16s "
           "ADDR=0x%-12llx LEN=%-8llu PROT=%s %s%s\n",
           e->event_type == 0 ? "MMAP    " : "MPROTECT",
           e->pid, e->ppid, e->comm,
           e->addr, e->length, prot,
           e->rwx       ? " RWX!"  : "",
           e->anonymous ? " ANON"    : "");

    return 0;
}

int main(void)
{
    struct kb_memory_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, handle_sigint);

    printf("╔══════════════════════════════════════════╗\n");
    printf("║  KB Core — Memory Monitor                ║\n");
    printf("║  Hook 6 / Weight: 15%%                   ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    skel = kb_memory_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = kb_memory_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach\n");
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.kb_memory_events),
        handle_event, NULL, NULL);
    if (!rb) goto cleanup;

    printf("%-10s %-6s %-6s %-16s %-14s %-8s %s\n",
           "TYPE", "PID", "PPID", "COMM", "ADDR", "LEN", "PROT");
    printf("──────────────────────────────────────────────\n");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

cleanup:
    ring_buffer__free(rb);
    kb_memory_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}