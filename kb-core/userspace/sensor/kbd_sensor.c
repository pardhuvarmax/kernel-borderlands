// SPDX-License-Identifier: GPL-2.0
// KB Core — Unified Sensor Userspace Loader
//
// Loads ALL 6 hooks at once from kbd_sensor.bpf.c, reads from
// the single shared ring buffer, and prints unified events.
//
// This is the binary that will eventually feed the gRPC
// Control Plane (Tejaswini's kbd daemon) via StreamEvents-style
// push, or a local Unix socket bridge. For now it prints to
// stdout so the pipeline can be visually verified end-to-end.

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "../.output/kbd_sensor.skel.h"

#define KB_EVT_PROCESS_EXEC      0
#define KB_EVT_PROCESS_EXIT      1
#define KB_EVT_SYSCALL           2
#define KB_EVT_PRIVILEGE_CHANGE  3
#define KB_EVT_FILE_ACCESS       4
#define KB_EVT_NETWORK_CONNECT   5
#define KB_EVT_NETWORK_BIND      6
#define KB_EVT_MEMORY_MMAP       7
#define KB_EVT_MEMORY_MPROTECT   8

struct kb_unified_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8  comm[16];
    __u8  event_type;
    __u64 ts_ns;

    __u32 syscall_nr;

    __u32 old_uid;
    __u32 new_uid;
    __u32 old_euid;
    __u32 new_euid;
    __u64 cap_effective;
    __u8  escalation;

    __u8  filename[128];
    __u8  sensitive;
    __u32 flags;

    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;

    __u64 addr;
    __u64 length;
    __u32 prot;
    __u32 mmap_flags;
    __u8  rwx;
    __u8  anonymous;
};

static volatile int running = 1;
void handle_sigint(int sig) { running = 0; }

static const char *event_type_name(__u8 t)
{
    switch (t) {
        case KB_EVT_PROCESS_EXEC:     return "process_exec";
        case KB_EVT_PROCESS_EXIT:     return "process_exit";
        case KB_EVT_SYSCALL:          return "syscall";
        case KB_EVT_PRIVILEGE_CHANGE: return "privilege_change";
        case KB_EVT_FILE_ACCESS:      return "file_access";
        case KB_EVT_NETWORK_CONNECT:  return "network_connect";
        case KB_EVT_NETWORK_BIND:     return "network_bind";
        case KB_EVT_MEMORY_MMAP:      return "memory_mmap";
        case KB_EVT_MEMORY_MPROTECT:  return "memory_mprotect";
        default:                      return "unknown";
    }
}

static void prot_str(__u32 prot, char *buf)
{
    buf[0] = (prot & 1) ? 'R' : '-';
    buf[1] = (prot & 2) ? 'W' : '-';
    buf[2] = (prot & 4) ? 'X' : '-';
    buf[3] = '\0';
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct kb_unified_event *e = data;

    // Suppress syscall noise — too frequent for clean demo output
    // Syscall entropy is still being sampled in-kernel (every 100
    // syscalls per process) and would feed the scoring engine in
    // the real pipeline; this only suppresses the printf display.
    if (e->event_type == KB_EVT_SYSCALL)
        return 0;

    char dst[INET_ADDRSTRLEN] = {0};
    char src[INET_ADDRSTRLEN] = {0};
    char prot[4];

    printf("[%-17s] PID=%-6u PPID=%-6u UID=%-5u COMM=%-16s ",
           event_type_name(e->event_type),
           e->pid, e->ppid, e->uid, e->comm);

    switch (e->event_type) {
        case KB_EVT_PROCESS_EXEC:
        case KB_EVT_PROCESS_EXIT:
            printf("\n");
            break;

        case KB_EVT_SYSCALL:
            printf("nr=%u\n", e->syscall_nr);
            break;

        case KB_EVT_PRIVILEGE_CHANGE:
            printf("uid:%u->%u euid:%u->%u %s\n",
                   e->old_uid, e->new_uid,
                   e->old_euid, e->new_euid,
                   e->escalation ? "🔴 ESCALATION" : "");
            break;

        case KB_EVT_FILE_ACCESS:
            printf("file=%s %s\n",
                   e->filename,
                   e->sensitive ? "🔴 SENSITIVE" : "");
            break;

        case KB_EVT_NETWORK_CONNECT:
            inet_ntop(AF_INET, &e->daddr, dst, sizeof(dst));
            printf("-> %s:%u\n", dst, e->dport);
            break;

        case KB_EVT_NETWORK_BIND:
            inet_ntop(AF_INET, &e->saddr, src, sizeof(src));
            printf("listen %s:%u\n", src, e->sport);
            break;

        case KB_EVT_MEMORY_MMAP:
        case KB_EVT_MEMORY_MPROTECT:
            prot_str(e->prot, prot);
            printf("addr=0x%llx len=%llu prot=%s %s%s\n",
                   (unsigned long long)e->addr,
                   (unsigned long long)e->length,
                   prot,
                   e->rwx ? "🔴 RWX! " : "",
                   e->anonymous ? "ANON" : "");
            break;

        default:
            printf("\n");
    }

    return 0;
}

int main(void)
{
    struct kbd_sensor_bpf *skel;
    struct ring_buffer    *rb = NULL;
    int err;

    signal(SIGINT, handle_sigint);

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   KB Unified Sensor — kbd-sensor             ║\n");
    printf("║   All 6 hooks, single ring buffer            ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    skel = kbd_sensor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = kbd_sensor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
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

    printf("All 6 hooks attached. Streaming unified events...\n");
    printf("Press Ctrl+C to stop.\n\n");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

    printf("\nShutting down kbd-sensor...\n");

cleanup:
    ring_buffer__free(rb);
    kbd_sensor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}