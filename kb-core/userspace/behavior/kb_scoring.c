// SPDX-License-Identifier: GPL-2.0
// KB Core — Behavior Engine scoring implementation

#include <string.h>
#include "../../include/kb_scoring.h"

static const double kb_weights[KB_DIM_COUNT] = {
    [KB_DIM_PROCESS]   = 0.20,
    [KB_DIM_SYSCALL]   = 0.25,
    [KB_DIM_PRIVILEGE] = 0.20,
    [KB_DIM_FILE]      = 0.10,
    [KB_DIM_NETWORK]   = 0.10,
    [KB_DIM_MEMORY]    = 0.15,
};

static kb_process_state_t table[KB_MAX_TRACKED_PROCS];

void kb_scoring_init(void) { memset(table, 0, sizeof(table)); }

static kb_process_state_t *find_or_create(uint32_t pid)
{
    uint32_t idx = pid % KB_MAX_TRACKED_PROCS;
    for (uint32_t i = 0; i < KB_MAX_TRACKED_PROCS; i++) {
        uint32_t slot = (idx + i) % KB_MAX_TRACKED_PROCS;
        if (table[slot].in_use && table[slot].pid == pid)
            return &table[slot];
        if (!table[slot].in_use) {
            memset(&table[slot], 0, sizeof(kb_process_state_t));
            table[slot].pid = pid;
            table[slot].in_use = 1;
            return &table[slot];
        }
    }
    return NULL; // table full — caller should log, not crash
}

kb_process_state_t *kb_scoring_get_state(uint32_t pid)
{
    uint32_t idx = pid % KB_MAX_TRACKED_PROCS;
    for (uint32_t i = 0; i < KB_MAX_TRACKED_PROCS; i++) {
        uint32_t slot = (idx + i) % KB_MAX_TRACKED_PROCS;
        if (table[slot].in_use && table[slot].pid == pid)
            return &table[slot];
        if (!table[slot].in_use) return NULL;
    }
    return NULL;
}

void kb_scoring_remove(uint32_t pid)
{
    kb_process_state_t *s = kb_scoring_get_state(pid);
    if (s) s->in_use = 0;
}

const char *kb_zone_name(kb_zone_t z)
{
    switch (z) {
        case KB_ZONE_SAFE:        return "SAFE";
        case KB_ZONE_SUSPICIOUS:  return "SUSPICIOUS";
        case KB_ZONE_BORDERLANDS: return "BORDERLANDS";
        default:                  return "UNKNOWN";
    }
}

// Per-event → raw dimension score (0-100). Starting heuristics —
// meant to be tuned, not final. Each event only updates its own
// dimension; other dimensions keep their last known value.
static void score_event(const struct kb_unified_event *e,
                         kb_dimension_t *dim, double *score)
{
    switch (e->event_type) {
        case 0: case 1: // EXEC / EXIT
            *dim = KB_DIM_PROCESS; *score = 5.0;
            break;
        case 3: // PRIVILEGE_CHANGE
            *dim = KB_DIM_PRIVILEGE;
            *score = e->escalation ? 80.0 : 10.0;
            break;
        case 4: // FILE_ACCESS
            *dim = KB_DIM_FILE;
            *score = e->sensitive ? 70.0 : 5.0;
            break;
        case 5: case 6: // NETWORK_CONNECT / BIND
            *dim = KB_DIM_NETWORK; *score = 15.0;
            break;
        case 7: case 8: // MEMORY_MMAP / MPROTECT
            *dim = KB_DIM_MEMORY;
            *score = e->rwx ? 90.0 : (e->anonymous ? 25.0 : 5.0);
            break;
        default:
            *dim = KB_DIM_PROCESS; *score = 0.0;
    }
}

static kb_zone_t classify(double ema)
{
    if (ema >= 75.0) return KB_ZONE_BORDERLANDS;
    if (ema >= 40.0) return KB_ZONE_SUSPICIOUS;
    return KB_ZONE_SAFE;
}

// Shared recompute path: given a process state whose dim_score[] has
// just been updated in one slot, recompute composite/EMA/zone and
// build the result. Used by both kb_scoring_update() and
// kb_scoring_update_syscall_entropy() so the two entry points can't
// drift out of sync on how a zone transition is derived.
static kb_scoring_result_t recompute(kb_process_state_t *s, uint64_t ts_ns)
{
    kb_scoring_result_t r = {0};

    double composite = 0.0;
    for (int i = 0; i < KB_DIM_COUNT; i++)
        composite += kb_weights[i] * s->dim_score[i];
    s->composite_score = composite;

    s->ema_score = (s->event_count == 0)
        ? composite
        : KB_EMA_ALPHA * composite + (1 - KB_EMA_ALPHA) * s->ema_score;

    kb_zone_t prev = s->zone;
    kb_zone_t next = classify(s->ema_score);

    s->event_count++;
    if (ts_ns) s->last_updated_ns = ts_ns;

    r.state = s;
    r.prev_zone = prev;
    if (next != prev) {
        s->zone = next;
        r.zone_changed = 1;
    }
    return r;
}

kb_scoring_result_t kb_scoring_update(const struct kb_unified_event *evt)
{
    kb_scoring_result_t r = {0};
    kb_process_state_t *s = find_or_create(evt->pid);
    if (!s) return r; // table full

    if (!s->has_identity) {
        s->ppid = evt->ppid;
        s->uid  = evt->uid;
        memcpy(s->comm, evt->comm, sizeof(s->comm));
        s->start_time_ns = evt->ts_ns;
        s->has_identity = 1;
    }

    kb_dimension_t dim; double raw;
    score_event(evt, &dim, &raw);
    s->dim_score[dim] = raw;

    r = recompute(s, evt->ts_ns);

    if (evt->event_type == KB_EVT_PROCESS_EXIT)
        s->in_use = 0;

    return r;
}

// Syscall-entropy dimension update. Fed by a separate periodic reader
// of kb_syscall_counts/kb_syscall_totals (see kbd_sensor.c), not by
// kb_unified_event — the unified ring buffer only carries a running
// per-pid total, not the per-syscall-number distribution needed for
// entropy. If the pid isn't already tracked (no non-syscall event has
// been seen for it yet), this creates its slot so KB_DIM_SYSCALL
// doesn't sit at 0 indefinitely for short-lived, syscall-only pids.
// Feeds dim_score[KB_DIM_SYSCALL] — this is the value that drives
// composite_score/ema_score/zone, so callers must pass a WINDOWED
// (sliding) entropy estimate, not a raw lifetime figure. See
// kb_scoring_set_syscall_entropy_lifetime() below for the advisory
// lifetime figure, which is tracked separately and does not affect
// scoring.
kb_scoring_result_t kb_scoring_update_syscall_entropy(uint32_t pid, double entropy_0_100, uint64_t ts_ns)
{
    kb_scoring_result_t r = {0};
    kb_process_state_t *s = find_or_create(pid);
    if (!s) return r; // table full

    if (entropy_0_100 < 0.0)   entropy_0_100 = 0.0;
    if (entropy_0_100 > 100.0) entropy_0_100 = 100.0;

    s->dim_score[KB_DIM_SYSCALL] = entropy_0_100;
    return recompute(s, ts_ns);
}

// Advisory-only — does not touch composite_score/ema_score/zone.
// No-op if the pid has no tracked slot yet (caller should invoke
// kb_scoring_update_syscall_entropy for the same pid first, in the
// same scan pass, which creates the slot if needed).
void kb_scoring_set_syscall_entropy_lifetime(uint32_t pid, double entropy_0_100)
{
    kb_process_state_t *s = kb_scoring_get_state(pid);
    if (!s) return;

    if (entropy_0_100 < 0.0)   entropy_0_100 = 0.0;
    if (entropy_0_100 > 100.0) entropy_0_100 = 100.0;

    s->syscall_entropy_lifetime = entropy_0_100;
}

int kb_scoring_has_identity(uint32_t pid)
{
    kb_process_state_t *s = kb_scoring_get_state(pid);
    return s ? s->has_identity : 0;
}

// Never overwrites an identity already set from a real kb_unified_event —
// /proc reads are a fallback for pids that predate the sensor, not a
// source of truth that should ever race against or clobber live data.
void kb_scoring_set_identity(uint32_t pid, const char comm[16],
                              uint32_t ppid, uint32_t uid,
                              uint64_t start_time_ns)
{
    kb_process_state_t *s = kb_scoring_get_state(pid);
    if (!s || s->has_identity) return;

    memcpy(s->comm, comm, sizeof(s->comm));
    s->ppid = ppid;
    s->uid  = uid;
    s->start_time_ns = start_time_ns;
    s->has_identity = 1;
}