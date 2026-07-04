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
#include <string.h>
#include <math.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../.output/kbd_sensor.skel.h"
#include "../../include/kb_scoring.h"
#include "../bridge/kb_bridge.h"

// Timestamp source for sends not triggered by a live kb_unified_event
// (i.e. the entropy scan). BPF-side ts_ns comes from bpf_ktime_get_ns()
// (CLOCK_MONOTONIC-based); mirror that clock here so values from both
// paths are comparable, not sending 0 as a placeholder.
static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Send a full ProcessState at most once every N events per process,
// plus always on zone change. Avoids hammering the socket on hot
// pids (e.g. tight syscall loops) while keeping the Go side's view
// reasonably fresh. Tune once Teju has real throughput numbers.
#define KB_STATE_SYNC_EVERY_N 20

// ── Syscall entropy scan (KB_DIM_SYSCALL, 25% weight) ──
//
// Computes two numbers per pid, once per scan:
//   1. WINDOWED entropy — from the DELTA in counts since the last
//      scan, EMA-smoothed across scans. This is what feeds
//      kb_scoring_update_syscall_entropy() and therefore drives
//      composite_score/ema_score/zone. Answers "is this process
//      behaving unusually right now."
//   2. LIFETIME entropy — from the raw cumulative counts/totals,
//      same as before. Advisory only, via
//      kb_scoring_set_syscall_entropy_lifetime(); does not affect
//      zone/composite. Answers "was this process ever unusual."
//
// kb_syscall_counts/kb_syscall_totals themselves are never reset in
// the kernel (cumulative for process lifetime) — the windowing
// happens entirely in userspace by diffing against a snapshot of the
// previous scan.
#define KB_ENTROPY_SCAN_EVERY_N_POLLS 10     // ~1s at the 100ms poll timeout below
#define KB_ENTROPY_MAX_TRACKED_PIDS   4096   // per-scan accumulator table size
#define KB_ENTROPY_SNAPSHOT_TABLE_SIZE 65536 // distinct (pid,syscall_nr) pairs remembered
                                              // across scans for delta computation; if this
                                              // fills, excess keys fall back to delta=0 for
                                              // that scan (self-corrects once older pids exit
                                              // and free slots — no eviction implemented)
#define KB_ENTROPY_MAX_MAP_ITER       50000  // hard cap on counts-map entries walked per scan —
                                              // bounds worst-case scan cost; entries past this
                                              // cap are silently skipped for that pass and picked
                                              // up on a later scan as counts keep accumulating.
                                              // NOTE: also caps how many keys can be diffed for
                                              // the window computation in the same pass.
#define KB_ENTROPY_LOG2_MAX_SYSCALLS  9.0    // log2(512) == log2(KB_MAX_SYSCALLS in the .bpf.c)
#define KB_ENTROPY_WINDOW_EMA_ALPHA   0.3    // smoothing across scans for the windowed value —
                                              // same alpha style as KB_EMA_ALPHA in kb_scoring.c

// Per-pid accumulator, reset every scan. Shared shape for both the
// lifetime pass and the window pass (used as two separate tables).
struct kb_entropy_acc {
    uint32_t pid;
    int      in_use;
    double   sum_neg_p_logp; // running Shannon entropy accumulator, in bits
};
static struct kb_entropy_acc lifetime_acc_table[KB_ENTROPY_MAX_TRACKED_PIDS];
static struct kb_entropy_acc window_acc_table[KB_ENTROPY_MAX_TRACKED_PIDS];

static struct kb_entropy_acc *acc_slot(struct kb_entropy_acc *table, uint32_t pid)
{
    uint32_t idx = pid % KB_ENTROPY_MAX_TRACKED_PIDS;
    for (uint32_t i = 0; i < KB_ENTROPY_MAX_TRACKED_PIDS; i++) {
        uint32_t slot = (idx + i) % KB_ENTROPY_MAX_TRACKED_PIDS;
        if (table[slot].in_use && table[slot].pid == pid)
            return &table[slot];
        if (!table[slot].in_use) {
            table[slot].pid = pid;
            table[slot].in_use = 1;
            table[slot].sum_neg_p_logp = 0.0;
            return &table[slot];
        }
    }
    return NULL; // table full this scan — dropped, retried next scan
}

// Persistent (NOT reset per scan) snapshot of each (pid,syscall_nr)
// key's count as of the last scan, so this scan can compute a delta.
struct kb_syscall_snapshot {
    uint64_t key;
    int      in_use;
    uint64_t last_count;
};
static struct kb_syscall_snapshot snapshot_table[KB_ENTROPY_SNAPSHOT_TABLE_SIZE];

static struct kb_syscall_snapshot *snapshot_slot(uint64_t key)
{
    uint32_t idx = (uint32_t)(key % KB_ENTROPY_SNAPSHOT_TABLE_SIZE);
    for (uint32_t i = 0; i < KB_ENTROPY_SNAPSHOT_TABLE_SIZE; i++) {
        uint32_t slot = (idx + i) % KB_ENTROPY_SNAPSHOT_TABLE_SIZE;
        if (snapshot_table[slot].in_use && snapshot_table[slot].key == key)
            return &snapshot_table[slot];
        if (!snapshot_table[slot].in_use) {
            snapshot_table[slot].key = key;
            snapshot_table[slot].in_use = 1;
            snapshot_table[slot].last_count = 0;
            return &snapshot_table[slot];
        }
    }
    return NULL; // snapshot table full — see KB_ENTROPY_SNAPSHOT_TABLE_SIZE note above
}

// Persistent (NOT reset per scan) EMA of the windowed entropy value,
// so a single noisy 1s sample doesn't itself cause a zone flap —
// the smoothing happens here, before the value ever reaches
// kb_scoring_update_syscall_entropy()'s own EMA over composite_score.
struct kb_window_ema {
    uint32_t pid;
    int      in_use;
    int      primed;   // false until the first real sample lands
    double   ema_0_100;
};
static struct kb_window_ema window_ema_table[KB_ENTROPY_MAX_TRACKED_PIDS];

static struct kb_window_ema *window_ema_slot(uint32_t pid)
{
    uint32_t idx = pid % KB_ENTROPY_MAX_TRACKED_PIDS;
    for (uint32_t i = 0; i < KB_ENTROPY_MAX_TRACKED_PIDS; i++) {
        uint32_t slot = (idx + i) % KB_ENTROPY_MAX_TRACKED_PIDS;
        if (window_ema_table[slot].in_use && window_ema_table[slot].pid == pid)
            return &window_ema_table[slot];
        if (!window_ema_table[slot].in_use) {
            window_ema_table[slot].pid = pid;
            window_ema_table[slot].in_use = 1;
            window_ema_table[slot].primed = 0;
            window_ema_table[slot].ema_0_100 = 0.0;
            return &window_ema_table[slot];
        }
    }
    return NULL; // table full — pid just won't get window smoothing this scan
}

// One (key, delta_count) pair collected during the map walk, resolved
// against per-pid delta totals in the second, in-memory-only pass.
// Static: ~50000 * 16 bytes = 800KB, avoids a giant stack frame.
struct kb_delta_entry { uint64_t key; uint64_t delta; };
static struct kb_delta_entry delta_buf[KB_ENTROPY_MAX_MAP_ITER];

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

// Send whatever kb_scoring gave us back for one pid, over the bridge.
// Shared by handle_event() and the entropy scan so the two send paths
// can't drift on framing/reconnect logic.
static void bridge_dispatch(kb_scoring_result_t r, uint64_t ts_ns)
{
    if (!r.state)
        return;

    bridge_ensure_connected();
    if (bridge_fd < 0)
        return;

    int err = 0;
    if (r.zone_changed) {
        err = kb_bridge_send_zone_transition(
            bridge_fd, r.state->pid, r.state->start_time_ns,
            r.prev_zone, r.state->zone, r.state->ema_score, ts_ns);
    }
    if (!err && (r.zone_changed ||
                 r.state->event_count % KB_STATE_SYNC_EVERY_N == 0)) {
        err = kb_bridge_send_state(bridge_fd, r.state);
    }
    if (err) {
        // Peer went away mid-write — drop and reconnect on the next
        // send rather than retry-looping here.
        kb_bridge_close(bridge_fd);
        bridge_fd = -1;
    }
}

// One pass over kb_syscall_counts computing both lifetime entropy
// (from raw cumulative values) and per-key deltas (for the window
// pass below), then a second, BPF-free pass resolving those deltas
// into per-pid windowed entropy. Bounded by KB_ENTROPY_MAX_MAP_ITER.
static void scan_syscall_entropy(struct kbd_sensor_bpf *skel)
{
    int counts_fd = bpf_map__fd(skel->maps.kb_syscall_counts);
    int totals_fd = bpf_map__fd(skel->maps.kb_syscall_totals);
    if (counts_fd < 0 || totals_fd < 0)
        return; // maps not present in this skeleton build — regen needed

    memset(lifetime_acc_table, 0, sizeof(lifetime_acc_table));
    memset(window_acc_table, 0, sizeof(window_acc_table));

    uint64_t key = 0, next_key;
    int have_key = 0;
    int iterations = 0;
    int delta_count_n = 0;

    // Pass 1 (live BPF map walk): lifetime accumulation + delta capture.
    while (bpf_map_get_next_key(counts_fd, have_key ? &key : NULL, &next_key) == 0) {
        key = next_key;
        have_key = 1;

        if (++iterations > KB_ENTROPY_MAX_MAP_ITER)
            break;

        uint64_t count = 0;
        if (bpf_map_lookup_elem(counts_fd, &key, &count) != 0 || count == 0)
            continue;

        uint32_t pid = (uint32_t)(key >> 32);

        // -- lifetime --
        uint64_t total = 0;
        if (bpf_map_lookup_elem(totals_fd, &pid, &total) == 0 && total > 0) {
            struct kb_entropy_acc *acc = acc_slot(lifetime_acc_table, pid);
            if (acc) {
                double p = (double)count / (double)total;
                if (p > 0.0)
                    acc->sum_neg_p_logp += -(p * (log(p) / log(2.0)));
            }
        }

        // -- delta capture (window input) --
        struct kb_syscall_snapshot *snap = snapshot_slot(key);
        if (snap) {
            uint64_t prev = snap->last_count;
            uint64_t delta = (count >= prev) ? (count - prev) : 0; // guard pid reuse / map churn
            snap->last_count = count;

            if (delta > 0 && delta_count_n < KB_ENTROPY_MAX_MAP_ITER) {
                delta_buf[delta_count_n].key   = key;
                delta_buf[delta_count_n].delta = delta;
                delta_count_n++;
            }
        }
    }

    // Pass 2 (in-memory only): per-pid delta totals, then per-key
    // probabilities against those totals — same Shannon computation
    // as lifetime, just over this scan's deltas instead of raw counts.
    static struct kb_entropy_acc pid_delta_total[KB_ENTROPY_MAX_TRACKED_PIDS];
    memset(pid_delta_total, 0, sizeof(pid_delta_total));

    for (int i = 0; i < delta_count_n; i++) {
        uint32_t pid = (uint32_t)(delta_buf[i].key >> 32);
        struct kb_entropy_acc *tot = acc_slot(pid_delta_total, pid);
        if (tot)
            tot->sum_neg_p_logp += (double)delta_buf[i].delta; // reusing field as a plain sum here
    }

    for (int i = 0; i < delta_count_n; i++) {
        uint32_t pid = (uint32_t)(delta_buf[i].key >> 32);
        struct kb_entropy_acc *tot = acc_slot(pid_delta_total, pid);
        if (!tot || tot->sum_neg_p_logp <= 0.0)
            continue;

        double p = (double)delta_buf[i].delta / tot->sum_neg_p_logp;
        struct kb_entropy_acc *acc = acc_slot(window_acc_table, pid);
        if (acc && p > 0.0)
            acc->sum_neg_p_logp += -(p * (log(p) / log(2.0)));
    }

    // Push lifetime figures (advisory, no scoring side effects).
    for (int i = 0; i < KB_ENTROPY_MAX_TRACKED_PIDS; i++) {
        if (!lifetime_acc_table[i].in_use)
            continue;
        double lifetime_0_100 =
            (lifetime_acc_table[i].sum_neg_p_logp / KB_ENTROPY_LOG2_MAX_SYSCALLS) * 100.0;
        kb_scoring_set_syscall_entropy_lifetime(lifetime_acc_table[i].pid, lifetime_0_100);
    }

    // Push windowed figures (drives scoring) — EMA-smooth across
    // scans first so one noisy 1s sample can't flap a zone on its own.
    for (int i = 0; i < KB_ENTROPY_MAX_TRACKED_PIDS; i++) {
        if (!window_acc_table[i].in_use)
            continue;

        uint32_t pid = window_acc_table[i].pid;
        double raw_0_100 =
            (window_acc_table[i].sum_neg_p_logp / KB_ENTROPY_LOG2_MAX_SYSCALLS) * 100.0;

        struct kb_window_ema *ema = window_ema_slot(pid);
        double smoothed = raw_0_100;
        if (ema) {
            smoothed = ema->primed
                ? KB_ENTROPY_WINDOW_EMA_ALPHA * raw_0_100
                  + (1 - KB_ENTROPY_WINDOW_EMA_ALPHA) * ema->ema_0_100
                : raw_0_100;
            ema->ema_0_100 = smoothed;
            ema->primed = 1;
        }

        uint64_t ts = now_ns();
        kb_scoring_result_t r = kb_scoring_update_syscall_entropy(pid, smoothed, ts);
        bridge_dispatch(r, ts);
    }
}

// KB_EVT_* macros and struct kb_unified_event now come from
// kb_scoring.h (already #included above) instead of being redefined
// here — this was the "kept in sync by hand" wart kb_scoring.h's
// header comment flagged; one definition now, not two.

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
    // KB_DIM_SYSCALL is scored separately: scan_syscall_entropy() polls
    // kb_syscall_counts/kb_syscall_totals directly, on its own cadence,
    // instead of going through this per-event path.
    if (e->event_type == KB_EVT_SYSCALL)
        return 0;

    // --- scoring + bridge send ---
    // e is already a struct kb_unified_event * (single shared
    // definition, from kb_scoring.h) — no cast needed.
    kb_scoring_result_t r = kb_scoring_update(e);
    bridge_dispatch(r, e->ts_ns);

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

    // Matches wire.go's envOr("KBD_SOCKET_PATH", "/var/run/kbd.sock") on
    // the Go side — both must agree or they'll never connect. Falls back
    // to KB_BRIDGE_DEFAULT_SOCK (bridge_sock_path's compiled-in default)
    // if unset, same as before this existed.
    const char *env_sock = getenv("KBD_SOCKET_PATH");
    if (env_sock)
        strncpy(bridge_sock_path, env_sock, sizeof(bridge_sock_path) - 1);

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

    int poll_count = 0;
    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;

        if (++poll_count >= KB_ENTROPY_SCAN_EVERY_N_POLLS) {
            poll_count = 0;
            scan_syscall_entropy(skel);
        }
    }

    printf("\nShutting down kbd-sensor...\n");

cleanup:
    kb_bridge_close(bridge_fd);
    ring_buffer__free(rb);
    kbd_sensor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}