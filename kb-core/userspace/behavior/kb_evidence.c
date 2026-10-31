// SPDX-License-Identifier: GPL-2.0
// KB Core — Evidence Accumulator Implementation

#include <string.h>
#include <stdint.h>
#include "../../include/kb_evidence.h"

// ── Evidence store (open-addressing hash table) ────────────────────────────
static kb_evidence_t store[KB_EVIDENCE_MAX_PROCS];

void kb_evidence_init(void)
{
    memset(store, 0, sizeof(store));
}

// Bounded-probe table. The old table probed linearly over the WHOLE table with
// hash = pid % N: sequential pids formed one giant cluster, so a lookup under a
// process storm (or after lost exit events left stale entries) scanned
// thousands of slots per event, 40-55% of the sensor's CPU, which made it slower
// exactly when it was behind. Now: scatter hash, look at KB_PROBE_MAX slots at
// most, and when that window is full evict its least-evidenced entry (never an
// entry with more evidence while a quieter one is available). Lookup cost is
// constant. It also no longer stops at an empty slot, so a freed slot cannot
// hide entries behind it.
#define KB_PROBE_MAX 64
static uint64_t evictions;
uint64_t kb_evidence_evictions(void) { return evictions; }

static uint32_t ev_slot(uint32_t pid)
{
    return (uint32_t)(((uint64_t)pid * 2654435761u) % KB_EVIDENCE_MAX_PROCS);
}

kb_evidence_t *kb_evidence_get(uint32_t pid)
{
    uint32_t idx = ev_slot(pid);
    for (uint32_t i = 0; i < KB_PROBE_MAX; i++) {
        uint32_t s = (idx + i) % KB_EVIDENCE_MAX_PROCS;
        if (store[s].in_use && store[s].pid == pid)
            return &store[s];
    }
    return NULL;
}

kb_evidence_t *kb_evidence_get_or_create(uint32_t pid, uint32_t ppid,
                                           uint32_t uid, const char *comm,
                                           uint64_t start_time_ns)
{
    uint32_t idx = ev_slot(pid);
    int free_slot = -1, victim = -1;
    int victim_imp = 1 << 30;
    for (uint32_t i = 0; i < KB_PROBE_MAX; i++) {
        uint32_t s = (idx + i) % KB_EVIDENCE_MAX_PROCS;
        if (store[s].in_use) {
            if (store[s].pid == pid)
                return &store[s];
            int imp = __builtin_popcountll(store[s].flags);
            if (imp < victim_imp) { victim_imp = imp; victim = (int)s; }
        } else if (free_slot < 0) {
            free_slot = (int)s;
        }
    }
    int s = free_slot >= 0 ? free_slot : victim;
    if (free_slot < 0)
        evictions++;
    memset(&store[s], 0, sizeof(kb_evidence_t));
    store[s].pid           = pid;
    store[s].ppid          = ppid;
    store[s].uid           = uid;
    store[s].start_time_ns = start_time_ns;
    store[s].in_use        = 1;
    if (comm)
        strncpy(store[s].comm, comm, sizeof(store[s].comm) - 1);
    return &store[s];
}

int kb_evidence_occupancy(void)
{
    int n = 0;
    for (uint32_t i = 0; i < KB_EVIDENCE_MAX_PROCS; i++)
        if (store[i].in_use) n++;
    return n;
}

// Linear probing without tombstones: rebuild the table from the survivors.
// (kb_evidence_remove below has the same chain-breaking weakness; a rebuild
// also repairs chains it damaged.)
int kb_evidence_reap(int (*alive)(uint32_t pid))
{
    static kb_evidence_t keep[KB_EVIDENCE_MAX_PROCS];
    int kept = 0, dropped = 0;
    for (uint32_t i = 0; i < KB_EVIDENCE_MAX_PROCS; i++) {
        if (!store[i].in_use)
            continue;
        if (alive(store[i].pid))
            keep[kept++] = store[i];
        else
            dropped++;
    }
    if (!dropped)
        return 0;
    memset(store, 0, sizeof(store));
    for (int k = 0; k < kept; k++) {
        uint32_t idx = ev_slot(keep[k].pid);
        for (uint32_t i = 0; i < KB_PROBE_MAX; i++) {
            uint32_t s = (idx + i) % KB_EVIDENCE_MAX_PROCS;
            if (!store[s].in_use) {
                store[s] = keep[k];
                break;
            }
        }
    }
    return dropped;
}

void kb_evidence_remove(uint32_t pid)
{
    kb_evidence_t *ev = kb_evidence_get(pid);
    if (ev) ev->in_use = 0;
}

// Set an evidence flag and record first-observation timestamps
void kb_evidence_set_flag(kb_evidence_t *ev, uint64_t flag, uint64_t ts_ns)
{
    if (!ev) return;

    // Record first-observation time per category
    if (!(ev->flags & flag)) {
        // First time this flag is set
        if (flag & (KB_EV_EXEC_FROM_TMP | KB_EV_EXEC_FROM_PROC |
                    KB_EV_SPAWNED_SHELL  | KB_EV_RAPID_EXEC_BURST)) {
            if (!ev->first_exec_ns) ev->first_exec_ns = ts_ns;
        }
        if (flag & (KB_EV_PRIVILEGE_GAINED | KB_EV_ROOT_ACHIEVED |
                    KB_EV_CAP_GAINED       | KB_EV_SETUID_ABUSE)) {
            if (!ev->first_privilege_ns) ev->first_privilege_ns = ts_ns;
        }
        if (flag & (KB_EV_RWX_MAPPING    | KB_EV_ANON_EXEC |
                    KB_EV_WX_TRANSITION  | KB_EV_PROC_MEM_WRITE |
                    KB_EV_PROCESS_VM_WRITE)) {
            if (!ev->first_rwx_ns) ev->first_rwx_ns = ts_ns;
        }
        if (flag & (KB_EV_OUTBOUND_CONNECT | KB_EV_NONSTANDARD_PORT |
                    KB_EV_C2_CANDIDATE_PORT | KB_EV_BIND_LISTENER)) {
            if (!ev->first_network_ns) ev->first_network_ns = ts_ns;
        }
        if (flag & (KB_EV_SHADOW_ACCESS | KB_EV_PASSWD_ACCESS |
                    KB_EV_SUDOERS_ACCESS | KB_EV_SSH_KEY_ACCESS)) {
            if (!ev->first_cred_file_ns) ev->first_cred_file_ns = ts_ns;
        }
    }

    ev->flags |= flag; // idempotent — OR in, never clear
}

// Append to the ordered sequence ring buffer
void kb_evidence_push_seq(kb_evidence_t *ev, kb_seq_event_t entry)
{
    if (!ev) return;
    ev->seq[ev->seq_head] = (kb_ev_seq_entry_t)entry;
    ev->seq_head = (ev->seq_head + 1) % KB_EVIDENCE_SEQ_LEN;
    if (ev->seq_len < KB_EVIDENCE_SEQ_LEN)
        ev->seq_len++;
}

// Copy sequence in chronological order into out_buf
int kb_evidence_get_seq(const kb_evidence_t *ev,
                          kb_ev_seq_entry_t *out_buf, int out_len)
{
    if (!ev || !out_buf || out_len <= 0) return 0;
    int n = ev->seq_len < out_len ? ev->seq_len : out_len;
    // oldest entry: (seq_head - seq_len + KB_EVIDENCE_SEQ_LEN) % KB_EVIDENCE_SEQ_LEN
    int start = (ev->seq_head - ev->seq_len + KB_EVIDENCE_SEQ_LEN) % KB_EVIDENCE_SEQ_LEN;
    for (int i = 0; i < n; i++) {
        out_buf[i] = ev->seq[(start + i) % KB_EVIDENCE_SEQ_LEN];
    }
    return n;
}

// Subsequence check: does the evidence sequence contain `pattern` in order?
// Greedy forward scan — O(seq_len * pattern_len) worst case, acceptable for small n.
int kb_evidence_seq_contains(const kb_evidence_t *ev,
                               const kb_ev_seq_entry_t *pattern, int pattern_len)
{
    if (!ev || !pattern || pattern_len <= 0) return 0;
    if (pattern_len > ev->seq_len) return 0;

    kb_ev_seq_entry_t buf[KB_EVIDENCE_SEQ_LEN];
    int n = kb_evidence_get_seq(ev, buf, KB_EVIDENCE_SEQ_LEN);

    int pi = 0; // pattern index
    for (int i = 0; i < n && pi < pattern_len; i++) {
        if (buf[i] == pattern[pi])
            pi++;
    }
    return pi == pattern_len;
}