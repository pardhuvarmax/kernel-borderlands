// SPDX-License-Identifier: GPL-2.0
// KB Core — Unified Sensor Userspace Loader
//
// Loads ALL 6 hooks at once from kbd_sensor.bpf.c, reads from
// the single shared ring buffer, and prints unified events.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <arpa/inet.h>
#include <elf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../.output/kbd_sensor.skel.h"
#include "../../include/kb_scoring.h"
#include "../../include/kb_evidence.h"
#include "../../include/kb_behavior.h"
#include "../../include/kb_rules.h"
#include "../bridge/kb_bridge.h"
#include "kb_sha256.h"
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>

// Timestamp source for sends not triggered by a live kb_unified_event
static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static kb_zone_t map_state_to_zone(kb_behavior_state_t state);

#define KB_STATE_SYNC_EVERY_N 20

// ── Syscall entropy scan (KB_DIM_SYSCALL, 25% weight) ──
#define KB_ENTROPY_SCAN_EVERY_N_POLLS 10
// CWP orphan-reconciliation sweep (docs/features/CWP.md §14.3) —
// approximate cadence only: ring_buffer__poll()'s 100ms timeout returns
// early on real events, so this is "every ~3000 idle-ish polls", not a
// precise timer. Deliberately low frequency per §15's performance
// requirement (sweep cost must stay independent of steady-state load).
#define KB_CWP_ORPHAN_SWEEP_EVERY_N_POLLS 3000
#define KB_ENTROPY_MAX_TRACKED_PIDS   4096   
#define KB_ENTROPY_SNAPSHOT_TABLE_SIZE 65536 
#define KB_ENTROPY_MAX_MAP_ITER       50000  
#define KB_ENTROPY_LOG2_MAX_SYSCALLS  9.0    
#define KB_ENTROPY_WINDOW_EMA_ALPHA   0.3    

struct kb_entropy_acc {
    uint32_t pid;
    int      in_use;
    double   sum_neg_p_logp; 
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
    return NULL; 
}

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
    return NULL; 
}

struct kb_window_ema {
    uint32_t pid;
    int      in_use;
    int      primed;   
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
    return NULL; 
}

struct kb_delta_entry { uint64_t key; uint64_t delta; };
static struct kb_delta_entry delta_buf[KB_ENTROPY_MAX_MAP_ITER];

// bridge_fd (kbd.sock): telemetry only, sensor -> Go, one direction.
// control_fd (kbct.sock): every Go -> sensor control push (containment
// commands, sensitive-path/rules pushes). Split so a telemetry-volume
// burst on bridge_fd can never stall or kill delivery of containment
// commands on control_fd — see KB_BRIDGE_CONTROL_SOCK's comment in
// kb_bridge.h for the failure mode this avoids.
static int   bridge_fd = -1;
static char  bridge_sock_path[108] = KB_BRIDGE_DEFAULT_SOCK;
static int   control_fd = -1;
static char  control_sock_path[108] = KB_BRIDGE_CONTROL_SOCK;

static void make_fd_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

static void bridge_ensure_connected(void)
{
    if (bridge_fd >= 0)
        return;
    bridge_fd = kb_bridge_try_connect(bridge_sock_path);
    if (bridge_fd >= 0) {
        make_fd_nonblocking(bridge_fd);
    }
}

static void control_ensure_connected(void)
{
    if (control_fd >= 0)
        return;
    control_fd = kb_bridge_try_connect(control_sock_path);
    if (control_fd >= 0) {
        make_fd_nonblocking(control_fd);
    }
}

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
        kb_bridge_close(bridge_fd);
        bridge_fd = -1;
    }
}

static void proc_backfill_identity(uint32_t pid)
{
    if (kb_scoring_has_identity(pid))
        return;

    char path[64], comm[16] = {0};

    snprintf(path, sizeof(path), "/proc/%u/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return; 
    if (fgets(comm, sizeof(comm), f)) {
        size_t n = strlen(comm);
        if (n && comm[n - 1] == '\n') comm[n - 1] = '\0';
    }
    fclose(f);

    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    f = fopen(path, "r");
    if (!f)
        return;
    char line[128];
    uint32_t ppid = 0, uid = 0xFFFFFFFF;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            ppid = strtoul(line + 5, NULL, 10);
        } else if (strncmp(line, "Uid:", 4) == 0) {
            uid = strtoul(line + 4, NULL, 10);
        }
    }
    fclose(f);

    uint64_t start_time_ns = 0;
    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    f = fopen(path, "r");
    if (f) {
        char stat_line[512];
        if (fgets(stat_line, sizeof(stat_line), f)) {
            char *tok = strrchr(stat_line, ')');
            if (tok) {
                int field = 3;
                tok = strtok(tok + 1, " ");
                while (tok && field < 22) { tok = strtok(NULL, " "); field++; }
                if (tok) {
                    unsigned long long ticks = strtoull(tok, NULL, 10);
                    long clk_tck = sysconf(_SC_CLK_TCK);
                    double starttime_s = (double)ticks / (double)clk_tck;

                    double uptime_s = 0.0;
                    FILE *uf = fopen("/proc/uptime", "r");
                    if (uf) {
                        if (fscanf(uf, "%lf", &uptime_s) != 1) uptime_s = 0.0;
                        fclose(uf);
                    }
                    double age_s = uptime_s - starttime_s;
                    if (age_s < 0) age_s = 0; 
                    start_time_ns = now_ns() - (uint64_t)(age_s * 1e9);
                }
            }
        }
        fclose(f);
    }

    kb_scoring_set_identity(pid, comm, ppid, uid, start_time_ns);
}

static void check_ringbuf_drops(struct kbd_sensor_bpf *skel)
{
    int fd = bpf_map__fd(skel->maps.kb_ringbuf_drops);
    if (fd < 0)
        return; 

    static uint64_t last_seen = 0;
    __u32 zero = 0;
    __u64 total = 0;
    if (bpf_map_lookup_elem(fd, &zero, &total) != 0)
        return;

    if (total > last_seen) {
        fprintf(stderr,
            "kbd_sensor: ring buffer full — %llu event(s) dropped since start "
            "(+%llu since last check). kb_events is 1MB shared across all 9 "
            "hooks; a burst (e.g. a `go build` spawning many short-lived "
            "processes) can exceed that. Dropped exec/exit events are the "
            "likely cause of blank comm on very short-lived pids.\n",
            (unsigned long long)total, (unsigned long long)(total - last_seen));
        last_seen = total;
    }
}

static void scan_syscall_entropy(struct kbd_sensor_bpf *skel)
{
    int counts_fd = bpf_map__fd(skel->maps.kb_syscall_counts);
    int totals_fd = bpf_map__fd(skel->maps.kb_syscall_totals);
    if (counts_fd < 0 || totals_fd < 0)
        return; 

    memset(lifetime_acc_table, 0, sizeof(lifetime_acc_table));
    memset(window_acc_table, 0, sizeof(window_acc_table));

    uint64_t key = 0, next_key;
    int have_key = 0;
    int iterations = 0;
    int delta_count_n = 0;

    while (bpf_map_get_next_key(counts_fd, have_key ? &key : NULL, &next_key) == 0) {
        key = next_key;
        have_key = 1;

        if (++iterations > KB_ENTROPY_MAX_MAP_ITER)
            break;

        uint64_t count = 0;
        if (bpf_map_lookup_elem(counts_fd, &key, &count) != 0 || count == 0)
            continue;

        uint32_t pid = (uint32_t)(key >> 32);

        proc_backfill_identity(pid);

        struct kb_entropy_acc *acc = acc_slot(lifetime_acc_table, pid);
        if (acc) {
            uint64_t pid_total = 0;
            if (bpf_map_lookup_elem(totals_fd, &pid, &pid_total) == 0 && pid_total > 0) {
                double p = (double)count / (double)pid_total;
                acc->sum_neg_p_logp += -p * (log2(p) / KB_ENTROPY_LOG2_MAX_SYSCALLS);
            }
        }

        struct kb_syscall_snapshot *snap = snapshot_slot(key);
        if (snap) {
            uint64_t delta = (count > snap->last_count) ? (count - snap->last_count) : 0;
            snap->last_count = count;

            if (delta > 0) {
                delta_buf[delta_count_n].key = key;
                delta_buf[delta_count_n].delta = delta;
                delta_count_n++;
            }
        }
    }

    check_ringbuf_drops(skel);

    for (int i = 0; i < delta_count_n; i++) {
        uint32_t pid = (uint32_t)(delta_buf[i].key >> 32);
        uint64_t delta = delta_buf[i].delta;

        uint64_t pid_delta_total = 0;
        for (int j = 0; j < delta_count_n; j++) {
            if ((uint32_t)(delta_buf[j].key >> 32) == pid) {
                pid_delta_total += delta_buf[j].delta;
            }
        }

        if (pid_delta_total > 0) {
            struct kb_entropy_acc *acc = acc_slot(window_acc_table, pid);
            if (acc) {
                double p = (double)delta / (double)pid_delta_total;
                acc->sum_neg_p_logp += -p * (log2(p) / KB_ENTROPY_LOG2_MAX_SYSCALLS);
            }
        }
    }

    uint64_t ts = now_ns();

    for (int i = 0; i < KB_ENTROPY_MAX_TRACKED_PIDS; i++) {
        if (lifetime_acc_table[i].in_use) {
            uint32_t pid = lifetime_acc_table[i].pid;
            double entropy_0_100 = lifetime_acc_table[i].sum_neg_p_logp * 100.0;
            if (entropy_0_100 > 100.0) entropy_0_100 = 100.0;
            kb_scoring_set_syscall_entropy_lifetime(pid, entropy_0_100);
        }
    }

    for (int i = 0; i < KB_ENTROPY_MAX_TRACKED_PIDS; i++) {
        if (window_acc_table[i].in_use) {
            uint32_t pid = window_acc_table[i].pid;
            double raw_entropy_0_100 = window_acc_table[i].sum_neg_p_logp * 100.0;
            if (raw_entropy_0_100 > 100.0) raw_entropy_0_100 = 100.0;

            struct kb_window_ema *w = window_ema_slot(pid);
            if (w) {
                double smoothed = w->ema_0_100;
                if (!w->primed) {
                    smoothed = raw_entropy_0_100;
                    w->primed = 1;
                } else {
                    smoothed = KB_ENTROPY_WINDOW_EMA_ALPHA * raw_entropy_0_100 +
                               (1 - KB_ENTROPY_WINDOW_EMA_ALPHA) * smoothed;
                }
                w->ema_0_100 = smoothed;

                kb_scoring_result_t r = kb_scoring_update_syscall_entropy(pid, smoothed, ts);
                
                if (r.state) {
                    kb_evidence_t *ev = kb_evidence_get_or_create(pid, r.state->ppid, r.state->uid, r.state->comm, r.state->start_time_ns);
                    if (ev) {
                        ev->advisory_ema = r.state->ema_score;
                        ev->advisory_composite = r.state->composite_score;

                        if (smoothed >= 60.0) {
                            kb_evidence_set_flag(ev, KB_EV_HIGH_SYSCALL_ENTROPY, ts);
                            kb_evidence_push_seq(ev, KB_SEQ_HIGH_ENTROPY);
                        }

                        kb_behavior_result_t r_beh = kb_behavior_evaluate(ev);
                        if (r_beh.state_changed) {
                            printf("[BEHAVIOR ENGINE] PID=%u COMM=%s State transition (entropy): %s -> %s (Reason: %s, Chain: %s)\n",
                                   pid, r.state->comm,
                                   kb_state_name(r_beh.prev_state),
                                   kb_state_name(r_beh.new_state),
                                   r_beh.reason_str,
                                   r_beh.chain_name ? r_beh.chain_name : "none");
                        }

                        kb_zone_t next_zone = map_state_to_zone(r_beh.record->state);
                        kb_zone_t prev_zone = r.state->zone;
                        r.state->zone = next_zone;
                        if (prev_zone != next_zone) {
                            r.zone_changed = 1;
                            r.prev_zone = prev_zone;
                        } else {
                            r.zone_changed = 0;
                        }
                    }
                }
                bridge_dispatch(r, ts);
            }
        }
    }
}

// kbd currently sends at most one frame at connect time (the
// sensitive_paths push below) — the rules push (msg_type 3) this
// function reads for is never actually sent by production Go code. Since
// this is a blind length-prefixed read (it must consume the bytes before
// it can even see the msg_type field inside them), if a sensitive_paths
// frame arrives here instead, it would otherwise be silently drained and
// discarded, leaving nothing for read_sensitive_paths_from_bridge() to
// read later. Stash it here instead of freeing it so that later call can
// use it, regardless of which frame actually shows up first on the wire.
static char     *pending_sensitive_paths_buf;
static uint32_t  pending_sensitive_paths_len;

static int read_rules_from_bridge(int fd)
{
    uint32_t payload_len = 0;
    if (read(fd, &payload_len, 4) != 4) {
        return -1;
    }

    char *buf = malloc(payload_len);
    if (!buf) return -1;

    size_t total = 0;
    while (total < payload_len) {
        ssize_t n = read(fd, buf + total, payload_len - total);
        if (n <= 0) {
            free(buf);
            return -1;
        }
        total += n;
    }

    if (payload_len < 8) {
        free(buf);
        return -1;
    }
    uint16_t magic = *(uint16_t *)buf;
    uint8_t version = buf[2];
    uint8_t msg_type = buf[3];
    if (magic != 0x4B42 || version != 3 || msg_type != 3) {
        if (magic == KB_WIRE_MAGIC && version == KB_WIRE_VERSION && msg_type == KB_WIRE_MSG_SENSITIVE_PATHS) {
            pending_sensitive_paths_buf = buf; // ownership transferred; freed by read_sensitive_paths_from_bridge
            pending_sensitive_paths_len = payload_len;
        } else {
            free(buf);
        }
        return -1;
    }

    uint32_t rule_count = *(uint32_t *)(buf + 4);
    size_t expected_size = 8 + rule_count * sizeof(struct kb_wire_attack_rule);
    if (payload_len < expected_size) {
        free(buf);
        return -1;
    }

    kb_rules_load_wire((const struct kb_wire_attack_rule *)(buf + 8), rule_count);
    free(buf);
    return 0;
}

#define KB_SENSITIVE_PATH_KEY_SIZE 64
// 4-byte header + 4-byte count + up to map-capacity (64) fixed-size keys.
// Bounding the payload up front and reading into a fixed stack buffer
// avoids the unbounded-malloc(payload_len) pattern read_rules_from_bridge
// above uses — kbd is a trusted local peer, but there's no reason to
// trust an arbitrary length here when the real maximum is known and small.
#define KB_SENSITIVE_PATHS_MAX_PAYLOAD (8 + 64 * KB_SENSITIVE_PATH_KEY_SIZE)

// Validates a sensitive-paths frame body (already fully read into buf,
// payload_len bytes) and merges its entries into the already-loaded
// kb_sensitive_paths BPF map, on top of the compiled-in floor
// populate_sensitive_paths() already wrote. Shared by both the
// stashed-frame and fresh-read paths in read_sensitive_paths_from_bridge
// below.
static int apply_sensitive_paths_frame(const char *buf, uint32_t payload_len, struct kbd_sensor_bpf *skel)
{
    if (payload_len < 8) {
        return -1;
    }
    uint16_t magic = *(const uint16_t *)buf;
    uint8_t version = buf[2];
    uint8_t msg_type = buf[3];
    if (magic != KB_WIRE_MAGIC || version != KB_WIRE_VERSION || msg_type != KB_WIRE_MSG_SENSITIVE_PATHS) {
        return -1;
    }

    uint32_t count = *(const uint32_t *)(buf + 4);
    size_t expected_size = 8 + (size_t)count * KB_SENSITIVE_PATH_KEY_SIZE;
    if (payload_len < expected_size) {
        return -1;
    }

    int map_fd = bpf_map__fd(skel->maps.kb_sensitive_paths);
    if (map_fd < 0) {
        fprintf(stderr, "apply_sensitive_paths_frame: failed to get kb_sensitive_paths map fd\n");
        return -1;
    }

    __u32 one = 1;
    for (uint32_t i = 0; i < count; i++) {
        char key[KB_SENSITIVE_PATH_KEY_SIZE] = {0};
        // Wire entries are already NUL-padded to 64 bytes by the Go
        // sender; copy defensively and force-terminate anyway since this
        // buffer crosses a process boundary.
        memcpy(key, buf + 8 + (size_t)i * KB_SENSITIVE_PATH_KEY_SIZE, KB_SENSITIVE_PATH_KEY_SIZE);
        key[KB_SENSITIVE_PATH_KEY_SIZE - 1] = '\0';
        int err = bpf_map_update_elem(map_fd, key, &one, BPF_ANY);
        if (err) {
            fprintf(stderr, "[PATH AUDITOR] Failed to add operator sensitive path %s: %d\n", key, err);
        } else {
            printf("[PATH AUDITOR] Registered operator sensitive path prefix: %s\n", key);
        }
    }

    return 0;
}

// Applies the operator-supplied sensitive_paths push from kbd (if any).
// Must be called after the skeleton is loaded (the map doesn't exist
// before that), unlike read_rules_from_bridge above which only touches a
// userspace table and can run earlier — which is exactly why this frame
// might already have arrived and been stashed by read_rules_from_bridge
// (kbd sends this frame immediately at connect, before the sensor has
// even finished loading BPF programs). Check that stash first; only fall
// back to a fresh blocking read if nothing was stashed, in case kbd's
// send is simply still in flight. Returns 0 on success (including "kbd
// sent nothing to add"), -1 on any framing/read error — callers should
// treat -1 as "compiled-in floor only, unchanged" rather than fatal.
static int read_sensitive_paths_from_bridge(int fd, struct kbd_sensor_bpf *skel)
{
    if (pending_sensitive_paths_buf) {
        int rc = apply_sensitive_paths_frame(pending_sensitive_paths_buf, pending_sensitive_paths_len, skel);
        free(pending_sensitive_paths_buf);
        pending_sensitive_paths_buf = NULL;
        pending_sensitive_paths_len = 0;
        return rc;
    }

    uint32_t payload_len = 0;
    if (read(fd, &payload_len, 4) != 4) {
        return -1;
    }
    if (payload_len < 8 || payload_len > KB_SENSITIVE_PATHS_MAX_PAYLOAD) {
        return -1;
    }

    char buf[KB_SENSITIVE_PATHS_MAX_PAYLOAD];
    size_t total = 0;
    while (total < payload_len) {
        ssize_t n = read(fd, buf + total, payload_len - total);
        if (n <= 0) {
            return -1;
        }
        total += n;
    }

    return apply_sensitive_paths_frame(buf, payload_len, skel);
}

// ── CPM (Critical Process Module) — docs/features/CPM.md ──
//
// Deliberate deviation from CPM.md §5.4's cpm_classify(), worth stating
// once, here: the spec sketches the classifier as in-kernel eBPF C
// operating on a live struct task_struct. In this codebase, containment
// is not decided synchronously in-kernel — kb-control-plane (Go) decides
// it and pushes a kb_wire_containment_cmd over the UDS bridge, and
// handle_incoming_containment_cmd() below is the sole place that ever
// writes a new entry into contained_pids_map. That function is the real
// "last gate before enforcement" (§4.2) in this codebase, so the
// classifier lives here in userspace C instead, gating the same map
// write the spec describes gating. The eBPF-side building blocks the
// spec calls for (protected_pids_map, the exec()-time registration hook,
// exit-time de-registration) are implemented in kbd_sensor.bpf.c exactly
// as specified — only this final decision function's location differs,
// to match where the actual choke point is.

enum cpm_decision {
    CPM_ALLOW,
    CPM_REJECT_KERNEL_THREAD,
    CPM_REJECT_PID1,
    CPM_REJECT_PROTECTED_PID,
    CPM_REJECT_PROTECTED_EXEC,
};

static const char *cpm_decision_reason(enum cpm_decision d)
{
    switch (d) {
        case CPM_REJECT_KERNEL_THREAD:  return "Kernel Thread";
        case CPM_REJECT_PID1:           return "Critical Operating System Process (PID 1)";
        case CPM_REJECT_PROTECTED_PID:  return "Protected PID";
        case CPM_REJECT_PROTECTED_EXEC: return "Protected Executable";
        default:                        return "Allowed";
    }
}

// task->mm == NULL (§3.2/§5.4) has no userspace equivalent pointer to
// read. A kernel thread has no /proc/<pid>/exe link, so readlink() on it
// fails — the standard userspace-visible signal for "this task has no
// associated mm", structural rather than name-based per §3.2's rationale.
static int cpm_is_kernel_thread(pid_t pid)
{
    char link_path[64];
    char target[PATH_MAX];
    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", (int)pid);
    ssize_t n = readlink(link_path, target, sizeof(target) - 1);
    return n < 0;
}

// Re-resolves the canonical exec path for an already-running PID. Used by
// the protected-exec re-check below, the /proc reconciliation scan
// (§7.1 item 3), and CPM audit logging. Returns 0 and fills path on
// success, -1 if unresolvable (process exited mid-check, permission
// denied, etc.) — callers must treat -1 as "can't confirm", not "not
// protected".
static int cpm_resolve_exec_path(pid_t pid, char *path, size_t path_len)
{
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", (int)pid);
    ssize_t n = readlink(link_path, path, path_len - 1);
    if (n < 0) return -1;
    path[n] = '\0';
    return 0;
}

static int cpm_exec_path_is_protected(struct kbd_sensor_bpf *skel, pid_t pid)
{
    char path[PATH_MAX];
    if (cpm_resolve_exec_path(pid, path, sizeof(path)) != 0)
        return 0;

    char key[64] = {0};
    strncpy(key, path, sizeof(key) - 1);

    int map_fd = bpf_map__fd(skel->maps.protected_exec_paths_map);
    if (map_fd < 0) return 0;

    __u8 val;
    return bpf_map_lookup_elem(map_fd, key, &val) == 0;
}

// §5.4's classifier, adapted to userspace per the file-header note above.
// Checks ordered cheapest/most-structural first, exactly as spec'd —
// first match short-circuits, no further checks run.
static enum cpm_decision cpm_classify(struct kbd_sensor_bpf *skel, pid_t pid)
{
    if (cpm_is_kernel_thread(pid))
        return CPM_REJECT_KERNEL_THREAD;

    if (pid == 1)
        return CPM_REJECT_PID1;

    int pids_fd = bpf_map__fd(skel->maps.protected_pids_map);
    if (pids_fd >= 0) {
        __u8 val;
        __u32 upid = (__u32)pid;
        if (bpf_map_lookup_elem(pids_fd, &upid, &val) == 0)
            return CPM_REJECT_PROTECTED_PID;
    }

    // §5.5 race-safety net: a process that just exec'd a protected binary
    // may not have landed in protected_pids_map yet if the exec
    // tracepoint hasn't been processed relative to this containment
    // command arriving. Re-check the live exec path directly instead of
    // trusting the map alone — CPM_ALLOW is never returned on this race.
    if (cpm_exec_path_is_protected(skel, pid))
        return CPM_REJECT_PROTECTED_EXEC;

    return CPM_ALLOW;
}

// §3.3/§7.1 item 2: register kbd_sensor's own PID unconditionally, before
// the bridge even connects — this doesn't depend on
// protected_exec_paths_map, since this process already exec'd before any
// hook could have caught it.
static void cpm_register_self(struct kbd_sensor_bpf *skel)
{
    int map_fd = bpf_map__fd(skel->maps.protected_pids_map);
    if (map_fd < 0) {
        fprintf(stderr, "[CPM] Failed to get protected_pids_map fd for self-registration\n");
        return;
    }
    __u32 pid = (__u32)getpid();
    __u8 one = 1;
    if (bpf_map_update_elem(map_fd, &pid, &one, BPF_ANY) != 0) {
        fprintf(stderr, "[CPM] Failed to self-register kbd_sensor PID %u\n", pid);
    } else {
        printf("[CPM] Self-registered kbd_sensor PID %u as protected (Sensor Self-Protection)\n", pid);
    }
}

// §7.1 item 3: scan already-running processes at startup and pre-register
// any whose canonical exec path matches the (already-populated) floor
// registry, so protection isn't delayed until their next restart.
static void cpm_reconcile_running_processes(struct kbd_sensor_bpf *skel)
{
    int pids_fd = bpf_map__fd(skel->maps.protected_pids_map);
    if (pids_fd < 0) return;

    DIR *proc = opendir("/proc");
    if (!proc) {
        fprintf(stderr, "[CPM] Failed to open /proc for startup reconciliation scan\n");
        return;
    }

    struct dirent *ent;
    __u8 one = 1;
    int registered = 0;
    while ((ent = readdir(proc)) != NULL) {
        char *end;
        long pid = strtol(ent->d_name, &end, 10);
        if (*end != '\0' || pid <= 0) continue; // not a /proc/<pid> directory

        if (cpm_exec_path_is_protected(skel, (pid_t)pid)) {
            __u32 upid = (__u32)pid;
            if (bpf_map_update_elem(pids_fd, &upid, &one, BPF_ANY) == 0)
                registered++;
        }
    }
    closedir(proc);
    printf("[CPM] Startup reconciliation: pre-registered %d already-running protected process(es)\n", registered);
}

// Compiled-in floor (§3.1/§5.2). kbctl is deliberately NOT listed here — it's
// a one-shot CLI (not a daemon), has no systemd unit, and its install path
// isn't documented anywhere in this repo; guessing wrong would silently fail
// to protect it while appearing to. kbd_sensor protects itself via
// cpm_register_self() instead, which doesn't depend on this registry.
//
// kb-checker and kbd ARE listed below: their install paths are documented at
// /usr/local/bin/kb-checker and /usr/local/bin/kbd in their respective
// systemd ExecStart= lines (docs/architecture/boot_sequence_spec.md).
// Protecting kbd's PID/exec-path also covers CPM.md's "policy-engine" —
// policy evaluation (kb-control-plane/internal/policy/) runs inside the kbd
// process, not as a separate binary, so there's nothing distinct to add for
// it. Without the kb-checker/kbd entries, a malfunctioning or manipulated
// detection engine could recommend either of them for containment through
// KB's own pipeline with nothing to stop it.
//
// kb-agent (kbagents.service, Ray Swarm node agent), kbopd (kbopd.service,
// operator dashboard), and kbopt (kbopt.service, SSH terminal console) are
// also listed below, at /usr/local/bin/kbagents, /usr/local/bin/kbopd, and
// /usr/local/bin/kbopt respectively, per the unit files now written into
// docs/architecture/boot_sequence_spec.md.
// NOTE: unlike kb-checker/kbd, kbagents and kbopd are packaging *decisions*,
// not builds that exist yet — kb-aads (kb-aads/main.py) currently runs as
// `python3 main.py`, and kb-op/kb-dashboard currently runs only via `npm run
// dev` (Vite dev-server) — neither has a compiled-binary install step
// producing these paths anywhere in this repo. Those two floor entries
// protect nothing in practice yet (no process execs from either path) but
// are harmless and become correct the moment each is packaged.
// kbopt is different: kb-tui already has a real compiled-binary build step
// (`go build -o kb-tui cmd/main.go`) — only the /usr/local/bin/kbopt install
// path/unit file was missing, not the packaging step, so this entry is
// closer to kb-checker/kbd in that a real binary just needs to land there.
static void populate_protected_exec_paths(struct kbd_sensor_bpf *skel)
{
    int map_fd = bpf_map__fd(skel->maps.protected_exec_paths_map);
    if (map_fd < 0) {
        fprintf(stderr, "[CPM] Failed to get file descriptor for protected_exec_paths_map\n");
        return;
    }

    const char *paths[] = {
        "/usr/lib/systemd/systemd",
        "/lib/systemd/systemd",
        "/usr/lib/systemd/systemd-logind",
        "/lib/systemd/systemd-logind",
        "/usr/lib/systemd/systemd-udevd",
        "/lib/systemd/systemd-udevd",
        "/usr/bin/dbus-daemon",
        "/usr/bin/NetworkManager",
        "/usr/sbin/NetworkManager",
        "/usr/local/bin/kb-checker",
        "/usr/local/bin/kbd",
        "/usr/local/bin/kbagents",
        "/usr/local/bin/kbopd",
        "/usr/local/bin/kbopt",
    };
    __u8 one = 1;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        char key[64] = {0};
        strncpy(key, paths[i], sizeof(key) - 1);
        int err = bpf_map_update_elem(map_fd, key, &one, BPF_ANY);
        if (err) {
            fprintf(stderr, "[CPM] Failed to add protected executable %s: %d\n", paths[i], err);
        } else {
            printf("[CPM] Registered protected executable: %s\n", paths[i]);
        }
    }
}

#define KB_CPM_PROTECTED_EXEC_KEY_SIZE 64
#define KB_CPM_PROTECTED_EXEC_MAX_PAYLOAD (8 + 64 * KB_CPM_PROTECTED_EXEC_KEY_SIZE)

// Validates and merges an operator-pushed protected-exec frame (§7.4)
// into protected_exec_paths_map, on top of the compiled-in floor above.
// Same shape/validation as apply_sensitive_paths_frame().
static int apply_cpm_protected_exec_frame(const char *buf, uint32_t payload_len, struct kbd_sensor_bpf *skel)
{
    if (payload_len < 8) return -1;
    uint16_t magic = *(const uint16_t *)buf;
    uint8_t version = buf[2];
    uint8_t msg_type = buf[3];
    if (magic != KB_WIRE_MAGIC || version != KB_WIRE_VERSION || msg_type != KB_WIRE_MSG_CPM_PROTECTED_EXEC) {
        return -1;
    }

    uint32_t count = *(const uint32_t *)(buf + 4);
    size_t expected_size = 8 + (size_t)count * KB_CPM_PROTECTED_EXEC_KEY_SIZE;
    if (payload_len < expected_size) return -1;

    int map_fd = bpf_map__fd(skel->maps.protected_exec_paths_map);
    if (map_fd < 0) {
        fprintf(stderr, "apply_cpm_protected_exec_frame: failed to get protected_exec_paths_map fd\n");
        return -1;
    }

    __u8 one = 1;
    for (uint32_t i = 0; i < count; i++) {
        char key[KB_CPM_PROTECTED_EXEC_KEY_SIZE] = {0};
        memcpy(key, buf + 8 + (size_t)i * KB_CPM_PROTECTED_EXEC_KEY_SIZE, KB_CPM_PROTECTED_EXEC_KEY_SIZE);
        key[KB_CPM_PROTECTED_EXEC_KEY_SIZE - 1] = '\0';
        int err = bpf_map_update_elem(map_fd, key, &one, BPF_ANY);
        if (err) {
            fprintf(stderr, "[CPM] Failed to add operator-pushed protected executable %s: %d\n", key, err);
        } else {
            printf("[CPM] Registered operator-pushed protected executable: %s\n", key);
        }
    }
    return 0;
}

// Non-blocking runtime check for an operator-pushed protected-exec frame
// (msg_type KB_WIRE_MSG_CPM_PROTECTED_EXEC), mirrored on
// handle_incoming_containment_cmd's MSG_PEEK/MSG_DONTWAIT pattern rather
// than read_sensitive_paths_from_bridge's one-shot blocking startup read.
// Unlike sensitive_paths (which kbd guarantees sending once at connect —
// see that function's comment), kb-control-plane has no sender for this
// msg_type yet, so a blocking startup read here would just burn the
// SO_RCVTIMEO deadline on every run for a frame that never arrives.
// Checked opportunistically during the main poll loop instead: a no-op
// today, ready the moment a Go-side sender exists. Only consumes the
// frame if it recognizes the msg_type, so it never steals a
// containment-cmd frame meant for handle_incoming_containment_cmd.
static void read_cpm_protected_exec_from_bridge(int fd, struct kbd_sensor_bpf *skel)
{
    uint32_t length = 0;
    ssize_t n = recv(fd, &length, 4, MSG_PEEK | MSG_DONTWAIT);
    if (n < 4) return;
    if (length < 8 || length > KB_CPM_PROTECTED_EXEC_MAX_PAYLOAD) return;

    char pkt_buf[4 + KB_CPM_PROTECTED_EXEC_MAX_PAYLOAD];
    ssize_t peek_sz = recv(fd, pkt_buf, 4 + length, MSG_PEEK | MSG_DONTWAIT);
    if (peek_sz < (ssize_t)(4 + length)) return;

    uint8_t msg_type = (uint8_t)pkt_buf[4 + 3];
    if (msg_type != KB_WIRE_MSG_CPM_PROTECTED_EXEC) return; // not ours; leave for other readers

    recv(fd, pkt_buf, 4 + length, MSG_DONTWAIT);
    apply_cpm_protected_exec_frame(pkt_buf + 4, length, skel);
}

// ── CWP (Critical Workload Protection) — docs/features/CWP.md ──
//
// Evaluated strictly after CPM (§2.3, §8's Detection→CPM→CWP→LSM
// ordering) — cwp_classify() below is only ever called once
// cpm_classify() has already returned CPM_ALLOW (see
// handle_incoming_containment_cmd). Same userspace-classifier deviation
// CPM's file-header comment above already explains: the spec sketches
// this as in-kernel eBPF, but the real "last gate before enforcement"
// choke point is handle_incoming_containment_cmd(), so that's where
// this lives too.
//
// Two further simplifications scoped down deliberately for this pass
// (both called out again in the implementation record's follow-up
// list):
//  1. protected_workloads_map's value is a single tier byte, not the
//     full §6.1 {protected, identity_tier, policy_id} struct —
//     policy_id only matters for the owner_team/justification lookups
//     feeding severity-escalated SIEM alerting (§9), out of scope here.
//  2. There is no compiled-in path floor the way CPM has systemd/dbus:
//     CWP protects organization-specific business applications, which
//     have no universal, safe-to-guess default the way OS infrastructure
//     paths do. The registry is populated entirely from operator-pushed
//     KB_WIRE_MSG_CWP_WORKLOADS frames.

enum cwp_decision {
    CWP_ALLOW,
    CWP_REJECT_PROTECTED_PATH,
    CWP_REJECT_PROTECTED_HASH,
};

static const char *cwp_decision_reason(enum cwp_decision d)
{
    switch (d) {
        case CWP_REJECT_PROTECTED_PATH: return "Administrator Protected Workload (path)";
        case CWP_REJECT_PROTECTED_HASH: return "Administrator Protected Workload (hash-verified)";
        default:                        return "Allowed";
    }
}

#define CWP_IDENTITY_TIER_PATH 0
#define CWP_IDENTITY_TIER_HASH 1
#define CWP_MAX_REGISTRY_ENTRIES 64

// Userspace mirror of protected_workload_paths_map, holding the
// expected-hash bytes the BPF map has no room for (§6.2). Keyed by the
// same 64-byte zero-padded path strings used as BPF map keys. Populated
// exclusively by apply_cwp_workloads_frame() below.
struct cwp_registry_entry {
    char    path[64];
    uint8_t identity_tier;
    uint8_t expected_hash[KB_SHA256_DIGEST_SIZE];
};
static struct cwp_registry_entry cwp_registry[CWP_MAX_REGISTRY_ENTRIES];
static int cwp_registry_count;

static const struct cwp_registry_entry *cwp_registry_lookup(const char *key64)
{
    for (int i = 0; i < cwp_registry_count; i++) {
        if (memcmp(cwp_registry[i].path, key64, sizeof(cwp_registry[i].path)) == 0)
            return &cwp_registry[i];
    }
    return NULL;
}

// §5.4/§7 classifier, evaluated after CPM allows. Checks the fast path
// first (already-registered PID from the exec hook), falling back to a
// direct path re-check for the same exec/containment race CPM's own
// classifier defends against (§5.5).
static enum cwp_decision cwp_classify(struct kbd_sensor_bpf *skel, pid_t pid)
{
    __u8 tier;
    int found = 0;

    int workloads_fd = bpf_map__fd(skel->maps.protected_workloads_map);
    if (workloads_fd >= 0) {
        __u32 upid = (__u32)pid;
        if (bpf_map_lookup_elem(workloads_fd, &upid, &tier) == 0)
            found = 1;
    }

    char exec_path[PATH_MAX];
    int have_exec_path = (cpm_resolve_exec_path(pid, exec_path, sizeof(exec_path)) == 0);

    if (!found) {
        if (!have_exec_path)
            return CWP_ALLOW; // can't resolve identity; nothing to check against

        char key[64] = {0};
        strncpy(key, exec_path, sizeof(key) - 1);

        int paths_fd = bpf_map__fd(skel->maps.protected_workload_paths_map);
        if (paths_fd < 0) return CWP_ALLOW;
        if (bpf_map_lookup_elem(paths_fd, key, &tier) != 0)
            return CWP_ALLOW;
        found = 1;
    }

    if (!found) return CWP_ALLOW; // unreachable; defensive

    if (tier == CWP_IDENTITY_TIER_PATH)
        return CWP_REJECT_PROTECTED_PATH;

    // Hash tier: verification happens here, at containment-decision
    // time, not at registration — hashing arbitrary file content isn't
    // available in-kernel, and this is the choke point every containment
    // request already passes through (§2.6 "minimal, fast-path
    // evaluation" is why registration only carries the tier flag, not
    // the hash check itself).
    if (!have_exec_path) {
        // §2.2 fail-closed: can't confirm identity, so don't expose to
        // containment.
        printf("[CWP] Unable to resolve exec path for PID %d during hash verification — failing closed (protected)\n", (int)pid);
        return CWP_REJECT_PROTECTED_HASH;
    }

    char key[64] = {0};
    strncpy(key, exec_path, sizeof(key) - 1);
    const struct cwp_registry_entry *entry = cwp_registry_lookup(key);
    if (!entry) {
        // Registry entry vanished since this PID registered (e.g. an
        // operator push replaced it) — fail closed rather than silently
        // treat as unprotected.
        printf("[CWP] Hash-tier registry entry for %s missing at verification time — failing closed (protected)\n", exec_path);
        return CWP_REJECT_PROTECTED_HASH;
    }

    uint8_t actual_hash[KB_SHA256_DIGEST_SIZE];
    if (kb_sha256_cached_file(exec_path, actual_hash) != 0) {
        printf("[CWP] Failed to hash %s for identity verification — failing closed (protected)\n", exec_path);
        return CWP_REJECT_PROTECTED_HASH;
    }

    if (memcmp(actual_hash, entry->expected_hash, KB_SHA256_DIGEST_SIZE) != 0) {
        // Spoofed identity attempt (§7, §11.1, §13.3): this is NOT the
        // protected workload, regardless of path match — do not exempt
        // it from containment, but log distinctly from an ordinary
        // "not protected" outcome so this is investigable as a
        // potential attack, not silence.
        char expected_hex[65], actual_hex[65];
        kb_sha256_to_hex(entry->expected_hash, expected_hex);
        kb_sha256_to_hex(actual_hash, actual_hex);
        printf("[CWP] SECURITY EVENT — Identity Verification Failed\n"
               "Path: %s\nPID: %d\nExpected Hash: %s\nObserved Hash: %s\n"
               "Action: NOT registered as protected — eligible for normal containment\n",
               exec_path, (int)pid, expected_hex, actual_hex);
        return CWP_ALLOW;
    }

    return CWP_REJECT_PROTECTED_HASH;
}

// §3.3/§7.1: no compiled-in floor exists for CWP (see file-header note
// above) — kept as an explicit, named no-op rather than omitted, so the
// startup call sequence in main() mirrors CPM's exactly and this step
// isn't mistaken for one that was simply forgotten.
static void populate_cwp_workload_floor(void)
{
    printf("[CWP] No compiled-in workload floor (organization-specific by design) — awaiting operator policy push\n");
}

// §3.3 startup reconciliation: pre-register already-running processes
// whose exec path matches the (already wire-pushed, if any)
// protected_workload_paths_map. Hash-tier entries are registered here
// too without verifying the hash — verification is always deferred to
// cwp_classify() at containment-decision time (see that function's
// comment), so this only needs the cheap path lookup, same as CPM's own
// reconciliation scan.
static void cwp_reconcile_running_processes(struct kbd_sensor_bpf *skel)
{
    int workloads_fd = bpf_map__fd(skel->maps.protected_workloads_map);
    int paths_fd = bpf_map__fd(skel->maps.protected_workload_paths_map);
    if (workloads_fd < 0 || paths_fd < 0) return;

    DIR *proc = opendir("/proc");
    if (!proc) {
        fprintf(stderr, "[CWP] Failed to open /proc for startup reconciliation scan\n");
        return;
    }

    struct dirent *ent;
    int registered = 0;
    while ((ent = readdir(proc)) != NULL) {
        char *end;
        long pid = strtol(ent->d_name, &end, 10);
        if (*end != '\0' || pid <= 0) continue;

        char path[PATH_MAX];
        if (cpm_resolve_exec_path((pid_t)pid, path, sizeof(path)) != 0) continue;

        char key[64] = {0};
        strncpy(key, path, sizeof(key) - 1);

        __u8 tier;
        if (bpf_map_lookup_elem(paths_fd, key, &tier) != 0) continue;

        __u32 upid = (__u32)pid;
        if (bpf_map_update_elem(workloads_fd, &upid, &tier, BPF_ANY) == 0)
            registered++;
    }
    closedir(proc);
    printf("[CWP] Startup reconciliation: pre-registered %d already-running protected workload(s)\n", registered);
}

#define KB_CWP_WORKLOAD_KEY_SIZE 64
// path(64) + identity_tier(1) + expected_hash(32). No policy_id/
// owner_team/justification (see file-header note above) — those only
// feed alerting escalation, deferred this pass.
#define KB_CWP_WORKLOAD_ENTRY_SIZE (KB_CWP_WORKLOAD_KEY_SIZE + 1 + KB_SHA256_DIGEST_SIZE)
#define KB_CWP_WORKLOADS_MAX_PAYLOAD (8 + CWP_MAX_REGISTRY_ENTRIES * KB_CWP_WORKLOAD_ENTRY_SIZE)

// Validates and merges an operator-pushed workload-registry frame
// (§7.4) into both protected_workload_paths_map (BPF) and cwp_registry
// (userspace, for the hash bytes). Merge semantics, not replace — an
// entry with a path already present is updated in place, matching the
// codebase's existing sensitive-paths/protected-exec "additive overlay"
// pattern rather than a hard reset. (Policy *removal* — CWP.md §12.2's
// revocation_mode — has no wire representation yet; explicit follow-up.)
static int apply_cwp_workloads_frame(const char *buf, uint32_t payload_len, struct kbd_sensor_bpf *skel)
{
    if (payload_len < 8) return -1;
    uint16_t magic = *(const uint16_t *)buf;
    uint8_t version = buf[2];
    uint8_t msg_type = buf[3];
    if (magic != KB_WIRE_MAGIC || version != KB_WIRE_VERSION || msg_type != KB_WIRE_MSG_CWP_WORKLOADS) {
        return -1;
    }

    uint32_t count = *(const uint32_t *)(buf + 4);
    size_t expected_size = 8 + (size_t)count * KB_CWP_WORKLOAD_ENTRY_SIZE;
    if (payload_len < expected_size) return -1;

    int paths_fd = bpf_map__fd(skel->maps.protected_workload_paths_map);
    if (paths_fd < 0) {
        fprintf(stderr, "apply_cwp_workloads_frame: failed to get protected_workload_paths_map fd\n");
        return -1;
    }

    for (uint32_t i = 0; i < count && i < CWP_MAX_REGISTRY_ENTRIES; i++) {
        const char *raw = buf + 8 + (size_t)i * KB_CWP_WORKLOAD_ENTRY_SIZE;

        char key[KB_CWP_WORKLOAD_KEY_SIZE] = {0};
        memcpy(key, raw, KB_CWP_WORKLOAD_KEY_SIZE);
        key[KB_CWP_WORKLOAD_KEY_SIZE - 1] = '\0';

        uint8_t tier = (uint8_t)raw[KB_CWP_WORKLOAD_KEY_SIZE];
        if (tier != CWP_IDENTITY_TIER_PATH && tier != CWP_IDENTITY_TIER_HASH) {
            fprintf(stderr, "[CWP] Rejecting workload entry %s: invalid identity_tier %u\n", key, tier);
            continue;
        }

        int err = bpf_map_update_elem(paths_fd, key, &tier, BPF_ANY);
        if (err) {
            fprintf(stderr, "[CWP] Failed to add protected workload path %s: %d\n", key, err);
            continue;
        }

        struct cwp_registry_entry *slot = NULL;
        for (int j = 0; j < cwp_registry_count; j++) {
            if (memcmp(cwp_registry[j].path, key, sizeof(cwp_registry[j].path)) == 0) {
                slot = &cwp_registry[j];
                break;
            }
        }
        if (!slot && cwp_registry_count < CWP_MAX_REGISTRY_ENTRIES) {
            slot = &cwp_registry[cwp_registry_count++];
        }
        if (slot) {
            memcpy(slot->path, key, sizeof(slot->path));
            slot->identity_tier = tier;
            memcpy(slot->expected_hash, raw + KB_CWP_WORKLOAD_KEY_SIZE + 1, KB_SHA256_DIGEST_SIZE);
        }

        printf("[CWP] Registered protected workload: %s (tier=%s)\n",
               key, tier == CWP_IDENTITY_TIER_HASH ? "hash" : "path");
    }
    return 0;
}

// Non-blocking runtime check, mirrored on
// read_cpm_protected_exec_from_bridge's MSG_PEEK/MSG_DONTWAIT pattern —
// kb-control-plane has no sender for this msg_type yet either, so this
// is a no-op today, ready the moment one exists.
static void read_cwp_workloads_from_bridge(int fd, struct kbd_sensor_bpf *skel)
{
    uint32_t length = 0;
    ssize_t n = recv(fd, &length, 4, MSG_PEEK | MSG_DONTWAIT);
    if (n < 4) return;
    if (length < 8 || length > KB_CWP_WORKLOADS_MAX_PAYLOAD) return;

    char pkt_buf[4 + KB_CWP_WORKLOADS_MAX_PAYLOAD];
    ssize_t peek_sz = recv(fd, pkt_buf, 4 + length, MSG_PEEK | MSG_DONTWAIT);
    if (peek_sz < (ssize_t)(4 + length)) return;

    uint8_t msg_type = (uint8_t)pkt_buf[4 + 3];
    if (msg_type != KB_WIRE_MSG_CWP_WORKLOADS) return; // not ours; leave for other readers

    recv(fd, pkt_buf, 4 + length, MSG_DONTWAIT);
    apply_cwp_workloads_frame(pkt_buf + 4, length, skel);
}

// §14.3 periodic orphan-reconciliation sweep, distinct from startup
// reconciliation above: catches a protected_workloads_map entry whose
// exit hook was missed (unclean sensor restart mid-flight, hook attach
// race, etc.) by cross-checking each entry's liveness against /proc.
// Runs at low frequency (see KB_CWP_ORPHAN_SWEEP_EVERY_N_POLLS) and
// iterates only this map, bounded by its own max size — not the full
// process table (§15's performance requirement).
static void cwp_sweep_orphaned_entries(struct kbd_sensor_bpf *skel)
{
    int workloads_fd = bpf_map__fd(skel->maps.protected_workloads_map);
    if (workloads_fd < 0) return;

    __u32 key, next_key;
    int have_key = 0;
    int swept = 0;

    // bpf_map_get_next_key(fd, NULL, &next_key) starts iteration; delete
    // during iteration is safe for BPF_MAP_TYPE_HASH (each call
    // re-resolves from the given key), same pattern libbpf's own
    // examples use.
    while (bpf_map_get_next_key(workloads_fd, have_key ? &key : NULL, &next_key) == 0) {
        key = next_key;
        have_key = 1;

        char proc_path[32];
        snprintf(proc_path, sizeof(proc_path), "/proc/%u", key);
        if (access(proc_path, F_OK) != 0) {
            if (bpf_map_delete_elem(workloads_fd, &key) == 0) {
                swept++;
                // Deleting the current key breaks get_next_key's cursor
                // (the key it would resolve "next" from no longer
                // exists); restart iteration from the top. Bounded by
                // the map's own max size (8192), not process count.
                have_key = 0;
            }
        }
    }
    if (swept > 0)
        printf("[CWP] Orphan sweep: removed %d stale protected-workload entr%s\n",
               swept, swept == 1 ? "y" : "ies");
}

// Only ever called with control_fd (see main()'s poll loop) — resets that
// global specifically on a dead connection, not bridge_fd, so the two
// connections' reconnect tracking never cross-contaminate.
static void handle_incoming_containment_cmd(int fd, struct kbd_sensor_bpf *skel)
{
    uint32_t length = 0;
    ssize_t n = recv(fd, &length, 4, MSG_PEEK | MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        close(fd);
        control_fd = -1;
        return;
    }
    if (n == 0) {
        close(fd);
        control_fd = -1;
        return;
    }
    if (n < 4) return;

    if (length != sizeof(struct kb_wire_containment_cmd)) {
        char garbage[256];
        recv(fd, garbage, sizeof(garbage), MSG_DONTWAIT);
        return;
    }

    char pkt_buf[80];
    ssize_t peek_sz = recv(fd, pkt_buf, 4 + length, MSG_PEEK | MSG_DONTWAIT);
    if (peek_sz < 4 + length) {
        return;
    }

    recv(fd, pkt_buf, 4 + length, MSG_DONTWAIT);

    struct kb_wire_containment_cmd *cmd = (struct kb_wire_containment_cmd *)(pkt_buf + 4);
    if (cmd->hdr.magic != KB_WIRE_MAGIC || cmd->hdr.version != KB_WIRE_VERSION || cmd->hdr.msg_type != KB_WIRE_MSG_CONTAINMENT_CMD) {
        return;
    }

    uint32_t pid   = cmd->pid;
    uint32_t level = cmd->level;
    int map_fd = bpf_map__fd(skel->maps.contained_pids_map);
    if (map_fd >= 0) {
        if (level == 0) {
            /* level 0 == ContainmentNone: remove the map entry entirely so the
             * eBPF lsm hooks no longer see this PID as contained.
             * bpf_map_update_elem(..., 0, ...) would leave a {pid→0} entry in
             * the map — bpf_map_lookup_elem still returns a non-NULL pointer for
             * value 0, keeping the lsm/file_open guard active and polluting the
             * map for any future PID reuse of this slot. */
            if (bpf_map_delete_elem(map_fd, &pid) != 0 && errno != ENOENT) {
                fprintf(stderr, "[SENSOR] delete_elem failed for PID %u: %s\n", pid, strerror(errno));
            } else {
                printf("[SENSOR] Cleared containment for PID %u (Reason: %.64s)\n", pid, cmd->reason);
            }
        } else {
            /* CPM gate (docs/features/CPM.md): every write that would ADD
             * containment passes through cpm_classify() first — releasing
             * containment (level == 0, above) is never gated, only its
             * addition is. A rejection is logged and the map write is
             * skipped entirely; the process remains fully monitored, just
             * not contained (§8's "monitoring never stops"). */
            enum cpm_decision decision = cpm_classify(skel, (pid_t)pid);
            if (decision != CPM_ALLOW) {
                char exec_path[PATH_MAX];
                if (cpm_resolve_exec_path((pid_t)pid, exec_path, sizeof(exec_path)) != 0) {
                    strncpy(exec_path, "unresolvable", sizeof(exec_path) - 1);
                    exec_path[sizeof(exec_path) - 1] = '\0';
                }
                printf("[CPM] Containment Prevented\nPID: %u\nExec: %s\nReason: %s\n",
                       pid, exec_path, cpm_decision_reason(decision));
                return;
            }
            // CWP gate (docs/features/CWP.md §8): evaluated strictly
            // after CPM, never before and never merged with it — an
            // over-broad CWP policy can only ever protect a workload
            // CPM has already allowed through, never one it rejected.
            enum cwp_decision wdecision = cwp_classify(skel, (pid_t)pid);
            if (wdecision != CWP_ALLOW) {
                char exec_path[PATH_MAX];
                if (cpm_resolve_exec_path((pid_t)pid, exec_path, sizeof(exec_path)) != 0) {
                    strncpy(exec_path, "unresolvable", sizeof(exec_path) - 1);
                    exec_path[sizeof(exec_path) - 1] = '\0';
                }
                printf("[CWP] Containment Prevented\nPID: %u\nExecutable: %s\nReason: %s\n",
                       pid, exec_path, cwp_decision_reason(wdecision));
                return;
            }
            if (bpf_map_update_elem(map_fd, &pid, &level, BPF_ANY) != 0) {
                fprintf(stderr, "[SENSOR] update_elem failed for PID %u with level %u: %s\n", pid, level, strerror(errno));
            } else {
                printf("[SENSOR] Applied containment level %u to PID %u (Reason: %.64s)\n", level, pid, cmd->reason);
            }
        }
    }
}

static kb_zone_t map_state_to_zone(kb_behavior_state_t state)
{
    switch (state) {
        case KB_STATE_SAFE:
        case KB_STATE_OBSERVED:
            return KB_ZONE_SAFE;
        case KB_STATE_SUSPICIOUS:
            return KB_ZONE_SUSPICIOUS;
        case KB_STATE_BORDERLANDS:
        case KB_STATE_COMPROMISED:
        case KB_STATE_CONTAINED:
        case KB_STATE_RECOVERING:
            return KB_ZONE_BORDERLANDS;
        default:
            return KB_ZONE_SAFE;
    }
}

static kb_scoring_result_t process_behavior_and_score(const struct kb_unified_event *e)
{
    kb_scoring_result_t r = kb_scoring_update(e);
    if (!r.state)
        return r;

    uint64_t ts = e->ts_ns;
    uint32_t pid = e->pid;

    kb_evidence_t *ev = kb_evidence_get_or_create(pid, r.state->ppid, r.state->uid, r.state->comm, r.state->start_time_ns);
    if (ev) {
        ev->advisory_ema = r.state->ema_score;
        ev->advisory_composite = r.state->composite_score;

        switch (e->event_type) {
            case KB_EVT_PROCESS_EXEC:
                kb_evidence_set_flag(ev, KB_EV_NONE, ts);
                kb_evidence_push_seq(ev, KB_SEQ_EXEC);
                break;
            case KB_EVT_PRIVILEGE_CHANGE:
                if (e->new_euid == 0xFFFFFFFF) {
                    kb_evidence_set_flag(ev, KB_EV_CAP_GAINED, ts);
                    kb_evidence_push_seq(ev, KB_SEQ_PRIVILEGE_UP);
                } else if (e->escalation) {
                    kb_evidence_set_flag(ev, KB_EV_PRIVILEGE_GAINED, ts);
                    kb_evidence_push_seq(ev, KB_SEQ_PRIVILEGE_UP);
                    if (e->new_uid == 0) {
                        kb_evidence_set_flag(ev, KB_EV_ROOT_ACHIEVED, ts);
                        kb_evidence_push_seq(ev, KB_SEQ_PRIVILEGE_ROOT);
                    }
                }
                break;
            case KB_EVT_FILE_ACCESS:
                if (e->sensitive) {
                    if (strstr((const char *)e->filename, "shadow")) {
                        kb_evidence_set_flag(ev, KB_EV_SHADOW_ACCESS, ts);
                    } else if (strstr((const char *)e->filename, "passwd")) {
                        kb_evidence_set_flag(ev, KB_EV_PASSWD_ACCESS, ts);
                    } else if (strstr((const char *)e->filename, "sudoers")) {
                        kb_evidence_set_flag(ev, KB_EV_SUDOERS_ACCESS, ts);
                    } else {
                        kb_evidence_set_flag(ev, KB_EV_SSH_KEY_ACCESS, ts);
                    }
                    kb_evidence_push_seq(ev, KB_SEQ_SHADOW_ACCESS);
                }
                break;
            case KB_EVT_NETWORK_CONNECT:
                kb_evidence_set_flag(ev, KB_EV_OUTBOUND_CONNECT, ts);
                kb_evidence_push_seq(ev, KB_SEQ_OUTBOUND_CONNECT);
                if (e->dport == 4444 || e->dport == 1337) {
                    kb_evidence_set_flag(ev, KB_EV_C2_CANDIDATE_PORT, ts);
                    kb_evidence_push_seq(ev, KB_SEQ_C2_PORT);
                }
                break;
            case KB_EVT_NETWORK_BIND:
                kb_evidence_set_flag(ev, KB_EV_BIND_LISTENER, ts);
                kb_evidence_push_seq(ev, KB_SEQ_BIND_LISTEN);
                break;
            case KB_EVT_MEMORY_MMAP:
            case KB_EVT_MEMORY_MPROTECT:
                if (e->addr == 0 && e->rwx) {
                    kb_evidence_set_flag(ev, KB_EV_PROC_MEM_WRITE, ts);
                    kb_evidence_push_seq(ev, KB_SEQ_PROC_MEM_WRITE);
                } else if (e->rwx) {
                    kb_evidence_set_flag(ev, KB_EV_RWX_MAPPING, ts);
                    kb_evidence_push_seq(ev, KB_SEQ_RWX_MAP);
                }
                break;
            default:
                break;
        }

        kb_behavior_result_t r_beh = kb_behavior_evaluate(ev);
        if (r_beh.state_changed) {
            printf("[BEHAVIOR ENGINE] PID=%u COMM=%s State transition: %s -> %s (Reason: %s, Chain: %s)\n",
                   pid, r.state->comm,
                   kb_state_name(r_beh.prev_state),
                   kb_state_name(r_beh.new_state),
                   r_beh.reason_str,
                   r_beh.chain_name ? r_beh.chain_name : "none");
        }

        kb_zone_t next_zone = map_state_to_zone(r_beh.record->state);
        kb_zone_t prev_zone = r.state->zone;
        r.state->zone = next_zone;
        if (prev_zone != next_zone) {
            r.zone_changed = 1;
            r.prev_zone = prev_zone;
        } else {
            r.zone_changed = 0;
        }
    }

    return r;
}

static size_t find_elf_symbol_offset(const char *elf_path, const char *symbol_name)
{
    FILE *f = fopen(elf_path, "rb");
    if (!f) return 0;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
        fclose(f);
        return 0;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fclose(f);
        return 0;
    }

    Elf64_Shdr *shdrs = malloc(ehdr.e_shentsize * ehdr.e_shnum);
    if (!shdrs) {
        fclose(f);
        return 0;
    }

    if (fseek(f, ehdr.e_shoff, SEEK_SET) != 0 ||
        fread(shdrs, ehdr.e_shentsize, ehdr.e_shnum, f) != ehdr.e_shnum) {
        free(shdrs);
        fclose(f);
        return 0;
    }

    Elf64_Shdr *symtab_shdr = NULL;
    Elf64_Shdr *strtab_shdr = NULL;

    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab_shdr = &shdrs[i];
            strtab_shdr = &shdrs[shdrs[i].sh_link];
        } else if (shdrs[i].sh_type == SHT_DYNSYM && !symtab_shdr) {
            symtab_shdr = &shdrs[i];
            strtab_shdr = &shdrs[shdrs[i].sh_link];
        }
    }

    if (!symtab_shdr || !strtab_shdr) {
        free(shdrs);
        fclose(f);
        return 0;
    }

    size_t num_syms = symtab_shdr->sh_size / symtab_shdr->sh_entsize;
    Elf64_Sym *syms = malloc(symtab_shdr->sh_size);
    char *strs = malloc(strtab_shdr->sh_size);

    if (!syms || !strs) {
        free(syms);
        free(strs);
        free(shdrs);
        fclose(f);
        return 0;
    }

    if (fseek(f, symtab_shdr->sh_offset, SEEK_SET) != 0 ||
        fread(syms, 1, symtab_shdr->sh_size, f) != symtab_shdr->sh_size ||
        fseek(f, strtab_shdr->sh_offset, SEEK_SET) != 0 ||
        fread(strs, 1, strtab_shdr->sh_size, f) != strtab_shdr->sh_size) {
        free(syms);
        free(strs);
        free(shdrs);
        fclose(f);
        return 0;
    }

    size_t offset = 0;
    for (size_t i = 0; i < num_syms; i++) {
        const char *name = strs + syms[i].st_name;
        if (strcmp(name, symbol_name) == 0) {
            offset = syms[i].st_value;
            break;
        }
    }

    free(syms);
    free(strs);
    free(shdrs);
    fclose(f);
    return offset;
}

static void try_attach_go_tls(struct kbd_sensor_bpf *skel, uint32_t pid, const char *comm)
{
    if (pid == 0 || pid == getpid()) return;

    char exe_path[64];
    snprintf(exe_path, sizeof(exe_path), "/proc/%u/exe", pid);

    size_t offset = find_elf_symbol_offset(exe_path, "crypto/tls.(*Conn).Write");
    if (offset == 0) {
        offset = find_elf_symbol_offset(exe_path, "crypto/tls.(*Conn).write");
    }

    if (offset == 0) {
        return;
    }

    printf("[TLS DETECTOR] Found Go TLS binary for PID=%u (%s). Offset=0x%lx. Attaching uprobe...\n", 
           pid, comm, (unsigned long)offset);

    struct bpf_link *link = bpf_program__attach_uprobe(
        skel->progs.kb_go_tls_write, false, pid, exe_path, offset
    );
    if (!link) {
        fprintf(stderr, "Failed to attach Go TLS uprobe: %d\n", -errno);
    } else {
        printf("[TLS DETECTOR] Successfully attached Go TLS uprobe to PID=%u\n", pid);
    }
}

static const char *common_ssl_paths[] = {
    "/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/usr/lib/libssl.so.3",
    "/usr/lib/libssl.so.1.1",
    "/lib/libssl.so.3",
    "/lib/libssl.so.1.1"
};

static const char *common_gnutls_paths[] = {
    "/lib/x86_64-linux-gnu/libgnutls.so.30",
    "/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
    "/usr/lib/libgnutls.so.30",
    "/lib/libgnutls.so.30"
};

static const char *common_nss_paths[] = {
    "/usr/lib/x86_64-linux-gnu/libnss3.so",
    "/lib/x86_64-linux-gnu/libnss3.so",
    "/usr/lib/libnss3.so",
    "/lib/libnss3.so"
};

static void populate_sensitive_paths(struct kbd_sensor_bpf *skel)
{
    int map_fd = bpf_map__fd(skel->maps.kb_sensitive_paths);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get file descriptor for kb_sensitive_paths map\n");
        return;
    }

    // /etc/passwd is deliberately NOT in this list: it holds no credential
    // material on a modern shadow-password system, is world-readable by
    // design, and is opened by nearly every userland tool that resolves a
    // UID (ls -l, id, ps, sudo, ssh, ...). Kernel-blocking it (-EACCES)
    // breaks routine system operation for negligible security benefit.
    // Reads of it are still flagged for behavioral scoring via
    // KB_EV_PASSWD_ACCESS in the eBPF evidence path — this list only
    // controls the *hard* LSM block, not detection.
    const char *paths[] = {
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh/"
    };
    __u32 one = 1;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        char key[64] = {};
        strncpy(key, paths[i], sizeof(key) - 1);
        int err = bpf_map_update_elem(map_fd, key, &one, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to add path %s to sensitive path map: %d\n", paths[i], err);
        } else {
            printf("[PATH AUDITOR] Registered sensitive path prefix: %s\n", paths[i]);
        }
    }
}

static void attach_ssl_uprobes(struct kbd_sensor_bpf *skel)
{
    // 1. OpenSSL
    const char *libssl_path = NULL;
    for (size_t i = 0; i < sizeof(common_ssl_paths) / sizeof(common_ssl_paths[0]); i++) {
        if (access(common_ssl_paths[i], F_OK) == 0) {
            libssl_path = common_ssl_paths[i];
            break;
        }
    }
    if (libssl_path) {
        size_t offset = find_elf_symbol_offset(libssl_path, "SSL_write");
        if (offset > 0) {
            printf("[TLS DETECTOR] Found libssl.so at %s. SSL_write offset=0x%lx. Attaching uprobe...\n", libssl_path, (unsigned long)offset);
            struct bpf_link *link = bpf_program__attach_uprobe(
                skel->progs.kb_ssl_write, false, -1 /* all PIDs */, libssl_path, offset
            );
            if (!link) {
                fprintf(stderr, "Failed to attach OpenSSL SSL_write uprobe: %d\n", -errno);
            } else {
                printf("[TLS DETECTOR] Successfully attached OpenSSL uprobe\n");
            }
        }
    } else {
        printf("[TLS DETECTOR] Warning: libssl.so not found. OpenSSL uprobe disabled.\n");
    }

    // 2. GnuTLS
    const char *gnutls_path = NULL;
    for (size_t i = 0; i < sizeof(common_gnutls_paths) / sizeof(common_gnutls_paths[0]); i++) {
        if (access(common_gnutls_paths[i], F_OK) == 0) {
            gnutls_path = common_gnutls_paths[i];
            break;
        }
    }
    if (gnutls_path) {
        size_t offset = find_elf_symbol_offset(gnutls_path, "gnutls_record_send");
        if (offset > 0) {
            printf("[TLS DETECTOR] Found libgnutls.so at %s. gnutls_record_send offset=0x%lx. Attaching uprobe...\n", gnutls_path, (unsigned long)offset);
            struct bpf_link *link = bpf_program__attach_uprobe(
                skel->progs.kb_ssl_write, false, -1 /* all PIDs */, gnutls_path, offset
            );
            if (!link) {
                fprintf(stderr, "Failed to attach GnuTLS uprobe: %d\n", -errno);
            } else {
                printf("[TLS DETECTOR] Successfully attached GnuTLS uprobe\n");
            }
        }
    } else {
        printf("[TLS DETECTOR] Warning: libgnutls.so not found. GnuTLS uprobe disabled.\n");
    }

    // 3. NSS
    const char *nss_path = NULL;
    for (size_t i = 0; i < sizeof(common_nss_paths) / sizeof(common_nss_paths[0]); i++) {
        if (access(common_nss_paths[i], F_OK) == 0) {
            nss_path = common_nss_paths[i];
            break;
        }
    }
    if (nss_path) {
        size_t offset = find_elf_symbol_offset(nss_path, "PR_Write");
        if (offset > 0) {
            printf("[TLS DETECTOR] Found libnss3.so at %s. PR_Write offset=0x%lx. Attaching uprobe...\n", nss_path, (unsigned long)offset);
            struct bpf_link *link = bpf_program__attach_uprobe(
                skel->progs.kb_ssl_write, false, -1 /* all PIDs */, nss_path, offset
            );
            if (!link) {
                fprintf(stderr, "Failed to attach NSS uprobe: %d\n", -errno);
            } else {
                printf("[TLS DETECTOR] Successfully attached NSS uprobe\n");
            }
        }
    } else {
        printf("[TLS DETECTOR] Warning: libnss3.so not found. NSS uprobe disabled.\n");
    }
}

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
        case 9:                       return "tls_plaintext";
        case 10:                      return "telemetry_dropped";
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
    struct kbd_sensor_bpf *skel = ctx;
    const struct kb_unified_event *e = data;

    if (e->event_type == KB_EVT_SYSCALL)
        return 0;

    if (e->event_type != 9 && e->event_type != 10) {
        kb_scoring_result_t r = process_behavior_and_score(e);
        bridge_dispatch(r, e->ts_ns);
    }

    char dst[INET_ADDRSTRLEN] = {0};
    char src[INET_ADDRSTRLEN] = {0};
    char prot[4];

    if (e->event_type != 10) {
        printf("[%-17s] PID=%-6u PPID=%-6u UID=%-5u COMM=%-16s ",
               event_type_name(e->event_type),
               e->pid, e->ppid, e->uid, e->comm);
    }

    switch (e->event_type) {
        case KB_EVT_PROCESS_EXEC:
            try_attach_go_tls(skel, e->pid, (const char *)e->comm);
            printf("\n");
            break;

        case 10:
            printf("Overloaded Batch: PID %u occurred %llu times in the last second, %llu events dropped\n", e->pid, 100 + (unsigned long long)e->length, (unsigned long long)e->length);
            break;

        case KB_EVT_PROCESS_EXIT:
            bridge_ensure_connected();
            if (bridge_fd >= 0) {
                kb_bridge_send_process_exit(bridge_fd, e->pid, e->ts_ns, e->syscall_nr);
            }
            printf("exit_code=%d\n", e->syscall_nr);
            break;

        case KB_EVT_SYSCALL:
            printf("nr=%u\n", e->syscall_nr);
            break;

        case KB_EVT_PRIVILEGE_CHANGE:
            if (e->new_euid == 0xFFFFFFFF) {
                printf("🔴 SENSITIVE CAPABILITY PROBE: Cap=%u (%s)\n",
                       e->old_euid,
                       e->old_euid == 21 ? "CAP_SYS_ADMIN" :
                       e->old_euid == 19 ? "CAP_SYS_PTRACE" :
                       e->old_euid == 17 ? "CAP_SYS_RAWIO" :
                       e->old_euid == 1 ? "CAP_DAC_OVERRIDE" : "unknown");
            } else {
                printf("uid:%u->%u euid:%u->%u %s\n",
                       e->old_uid, e->new_uid,
                       e->old_euid, e->new_euid,
                       e->escalation ? "🔴 ESCALATION" : "");
            }
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
            if (e->addr == 0 && e->rwx) {
                printf("🔴 CROSS-PROCESS MEMORY INJECTION! TargetPID=%llu\n", (unsigned long long)e->length);
            } else {
                prot_str(e->prot, prot);
                printf("addr=0x%llx len=%llu prot=%s %s%s\n",
                       (unsigned long long)e->addr,
                       (unsigned long long)e->length,
                       prot,
                       e->rwx ? "🔴 RWX! " : "",
                       e->anonymous ? "ANON" : "");
            }
            break;

        case 9: // KB_EVT_TLS_PLAINTEXT
            printf("payload=\"%s\" (len=%u)\n", e->filename, e->flags);
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
    // write() to bridge_fd/control_fd after the Go peer has closed its end
    // raises SIGPIPE, whose default disposition kills the whole process —
    // not just that one send call. Under bursty telemetry load this could
    // take down BOTH connections at once via signal, regardless of which
    // fd triggered it, undoing the point of splitting them in the first
    // place. Ignore it and let write()'s normal -1/EPIPE return handle it.
    signal(SIGPIPE, SIG_IGN);
    kb_scoring_init();
    kb_evidence_init();
    kb_behavior_init();

    const char *env_sock = getenv("KBD_SOCKET_PATH");
    if (env_sock && env_sock[0] != '\0') {
        strncpy(bridge_sock_path,
            env_sock,
            sizeof(bridge_sock_path) - 1);
        bridge_sock_path[sizeof(bridge_sock_path) - 1] = '\0';
    }
    const char *env_ctrl_sock = getenv("KBD_CONTROL_SOCKET_PATH");
    if (env_ctrl_sock && env_ctrl_sock[0] != '\0') {
        strncpy(control_sock_path,
            env_ctrl_sock,
            sizeof(control_sock_path) - 1);
        control_sock_path[sizeof(control_sock_path) - 1] = '\0';
    }

    bridge_fd = kb_bridge_try_connect(bridge_sock_path);
    if (bridge_fd < 0) {
        fprintf(stderr, "kbd_sensor: telemetry bridge not connected yet (%s) — will retry on events\n",
                bridge_sock_path);
    }

    control_fd = kb_bridge_try_connect(control_sock_path);
    if (control_fd < 0) {
        fprintf(stderr, "kbd_sensor: control channel not connected yet (%s) — will retry\n",
                control_sock_path);
    } else {
        if (read_rules_from_bridge(control_fd) < 0) {
            fprintf(stderr, "kbd_sensor: failed to read rules from control plane, using default compiled rules\n");
        }
        // NOTE: control_fd is deliberately left blocking (with the
        // connect-time SO_RCVTIMEO deadline from kb_bridge.c) until after
        // read_sensitive_paths_from_bridge() runs below, post-skeleton-load.
        // Switching to non-blocking here first would race that later read
        // against EAGAIN if kbd's push hadn't fully landed yet.
    }

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   KB Unified Sensor — kbd-sensor             ║\n");
    printf("║   All 6 hooks, single ring buffer            ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    skel = kbd_sensor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    bpf_program__set_autoload(skel->progs.kb_ssl_write, true);
    bpf_program__set_autoload(skel->progs.kb_go_tls_write, true);
    bpf_program__set_autoload(skel->progs.kb_lsm_file_open, true);

    err = kbd_sensor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        kbd_sensor_bpf__destroy(skel);
        return 1;
    }

    populate_sensitive_paths(skel);

    // CPM (docs/features/CPM.md): populate the protected-executable
    // floor, self-register this sensor process, and reconcile
    // already-running protected processes — all before BPF programs
    // attach below, so no containment command can race ahead of
    // protection being in place. Order matters: the reconciliation scan
    // depends on protected_exec_paths_map already being populated.
    populate_protected_exec_paths(skel);
    cpm_register_self(skel);
    cpm_reconcile_running_processes(skel);

    // CWP (docs/features/CWP.md): no compiled-in floor to populate (see
    // populate_cwp_workload_floor's comment) and no self-registration
    // equivalent (CWP protects business workloads, not sensor
    // components — that's CPM's job). Startup reconciliation still
    // needs to run before BPF attach, same ordering reason as CPM's.
    populate_cwp_workload_floor();
    cwp_reconcile_running_processes(skel);

    // Merge in any operator-supplied additions from policy.yaml's
    // sensitive_paths (see kb-control-plane/internal/policy/policy.go),
    // pushed once by kbd right after accepting this connection. Must run
    // after populate_sensitive_paths() — the map doesn't exist until the
    // skeleton above is loaded. control_fd < 0 (no control plane yet) just
    // means the compiled-in floor above stands alone, same as always.
    if (control_fd >= 0) {
        if (read_sensitive_paths_from_bridge(control_fd, skel) < 0) {
            fprintf(stderr, "kbd_sensor: no additional sensitive paths from control plane, using compiled-in floor only\n");
        }
        make_fd_nonblocking(control_fd);
    }
    if (bridge_fd >= 0) {
        make_fd_nonblocking(bridge_fd);
    }

    err = kbd_sensor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    attach_ssl_uprobes(skel);

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.kb_events),
        handle_event, skel, NULL
    );
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("All 6 hooks attached. Streaming unified events...\n");
    printf("Press Ctrl+C to stop.\n\n");

    int poll_count = 0;
    int cwp_sweep_poll_count = 0;
    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;

        control_ensure_connected();
        if (control_fd >= 0) {
            read_cpm_protected_exec_from_bridge(control_fd, skel);
            read_cwp_workloads_from_bridge(control_fd, skel);
            handle_incoming_containment_cmd(control_fd, skel);
        }

        if (++poll_count >= KB_ENTROPY_SCAN_EVERY_N_POLLS) {
            poll_count = 0;
            scan_syscall_entropy(skel);
        }

        if (++cwp_sweep_poll_count >= KB_CWP_ORPHAN_SWEEP_EVERY_N_POLLS) {
            cwp_sweep_poll_count = 0;
            cwp_sweep_orphaned_entries(skel);
        }
    }

    printf("\nShutting down kbd-sensor...\n");

cleanup:
    kb_bridge_close(bridge_fd);
    kb_bridge_close(control_fd);
    ring_buffer__free(rb);
    kbd_sensor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}