#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "../.output/kb_privilege.skel.h"

struct kb_privilege_event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u32 old_uid;
    __u32 new_uid;
    __u32 old_gid;
    __u32 new_gid;
    __u32 old_euid;
    __u32 new_euid;
    __u64 cap_effective;
    __u64 ts_ns;
    __u8  escalation;
};

static volatile int running = 1;
void handle_sigint(int sig) { running = 0; }

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct kb_privilege_event *e = data;

    printf("[%s] PID=%-6u PPID=%-6u COMM=%-16s "
           "UID: %u→%u EUID: %u→%u CAP=0x%llx\n",
           e->escalation ? "ESCALATION" : "PRIV_CHANGE",
           e->pid, e->ppid, e->comm,
           e->old_uid, e->new_uid,
           e->old_euid, e->new_euid,
           e->cap_effective);

    return 0;
}

int main(void)
{
    struct kb_privilege_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, handle_sigint);

    printf("╔══════════════════════════════════════════╗\n");
    printf("║  KB Core — Privilege Monitor             ║\n");
    printf("║  Hook 3 / Weight: 20%%                   ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    skel = kb_privilege_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = kb_privilege_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach\n");
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.kb_privilege_events),
        handle_event, NULL, NULL);
    if (!rb) goto cleanup;

    printf("%-15s %-6s %-6s %-16s %s\n",
           "TYPE", "PID", "PPID", "COMM", "PRIVILEGE CHANGE");
    printf("──────────────────────────────────────────────\n");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

cleanup:
    ring_buffer__free(rb);
    kb_privilege_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}