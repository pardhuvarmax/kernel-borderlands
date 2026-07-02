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
#include "../../include/kb_scoring.h"
#include "../bridge/kb_bridge.h"

// Send a full ProcessState at most once every N events per process,
// plus always on zone change. Avoids hammering the socket on hot
// pids (e.g. tight syscall loops) while keeping the Go side's view
// reasonably fresh. Tune once Teju has real throughput numbers.
#define KB_STATE_SYNC_EVERY_N 20

static int   bridge_fd = -1;
static char  bridge_sock_path[108] = KB_BRIDGE_DEFAULT_SOCK;

// Reconnect on demand rather than crashing the sensor if kbd's
// listener isn't up yet / drops. Events are dropped (not buffered)
// while disconnected — buffering is a deliberate non-goal for now,
// call this out if Teju's side needs replay/backfill instead.
static void bridge_ensure_connected(void)
{
    if (bridge_fd >= 0)
        return;
    bridge_fd = kb_bridge_try_connect(bridge_sock_path);
}

#define KB_EVT_PROCESS_EXEC      0
#define KB_EVT_PROCESS_EXIT      1
#define KB_EVT_SYSCALL           2
#define KB_EVT_PRIVILEGE_CHANGE  3
#define KB_EVT_FILE_ACCESS       4
#define KB_EVT_NETWORK_CONNECT   5
#define KB_EVT_NETWORK_BIND      6
#define KB_EVT_MEMORY_MMAP       7
#define KB_EVT_MEMORY_MPROTECT   8

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

    // Suppress syscall noise — too frequent for clean demo output.
    // NOTE: this also means KB_DIM_SYSCALL never gets scored from
    // this path. Syscall entropy needs a separate periodic reader
    // over kb_syscall_counts/kb_syscall_totals feeding
    // kb_scoring_update_syscall_entropy() — that map isn't wired
    // into kbd_sensor.bpf.c yet, so KB_DIM_SYSCALL sits at 0 for now.
    if (e->event_type == KB_EVT_SYSCALL)
        return 0;

    // --- scoring + bridge send ---
    // kb_unified_event here and the one in kb_scoring.h are two
    // separate definitions kept in sync by hand (documented wart in
    // kb_scoring.h) — cast is safe as long as layouts match.
    kb_scoring_result_t r =
        kb_scoring_update((const struct kb_unified_event *)e);

    if (r.state) {
        bridge_ensure_connected();
        if (bridge_fd >= 0) {
            int err = 0;

            if (r.zone_changed) {
                err = kb_bridge_send_zone_transition(
                    bridge_fd, r.state->pid, r.prev_zone, r.state->zone,
                    r.state->ema_score, e->ts_ns);
            }

            if (!err && (r.zone_changed ||
                         r.state->event_count % KB_STATE_SYNC_EVERY_N == 0)) {
                err = kb_bridge_send_state(bridge_fd, r.state);
            }

            if (err) {
                // Peer went away mid-write — drop and reconnect on
                // the next event rather than retry-looping here.
                kb_bridge_close(bridge_fd);
                bridge_fd = -1;
            }
        }
    }

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
    kb_scoring_init();

    // Best-effort connect at startup; if kbd's listener isn't up yet
    // this just falls through and handle_event()'s bridge_ensure_connected()
    // retries opportunistically on later events. Not a fatal condition —
    // the sensor should still run (and print) even with no bridge peer.
    bridge_fd = kb_bridge_try_connect(bridge_sock_path);
    if (bridge_fd < 0)
        fprintf(stderr, "kbd_sensor: bridge not connected yet (%s) — will retry on events\n",
                bridge_sock_path);

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
    kb_bridge_close(bridge_fd);
    ring_buffer__free(rb);
    kbd_sensor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}