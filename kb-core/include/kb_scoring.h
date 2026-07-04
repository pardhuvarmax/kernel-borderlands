// SPDX-License-Identifier: GPL-2.0
// KB Core — Behavior Engine scoring interface
//
// Consumes struct kb_unified_event as emitted by kbd_sensor.bpf.c /
// printed by kbd_sensor.c's handle_event(). This header intentionally
// does not include the BPF skeleton — kb_scoring.c has no BPF deps.

#ifndef KB_SCORING_H
#define KB_SCORING_H

#include <stdint.h>

#define KB_MAX_TRACKED_PROCS 10240
#define KB_EMA_ALPHA         0.3   // weight on new sample vs history

typedef enum {
    KB_DIM_PROCESS   = 0,  // 20%
    KB_DIM_SYSCALL   = 1,  // 25% — NOT scored from kb_unified_event, see note in kb_scoring.c
    KB_DIM_PRIVILEGE = 2,  // 20%
    KB_DIM_FILE      = 3,  // 10%
    KB_DIM_NETWORK   = 4,  // 10%
    KB_DIM_MEMORY    = 5,  // 15%
    KB_DIM_COUNT     = 6,
} kb_dimension_t;

typedef enum {
    KB_ZONE_SAFE        = 0,
    KB_ZONE_SUSPICIOUS  = 1,
    KB_ZONE_BORDERLANDS = 2,
} kb_zone_t;

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
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint8_t  comm[16];
    uint8_t  event_type;
    uint64_t ts_ns;

    uint32_t syscall_nr;

    uint32_t old_uid;
    uint32_t new_uid;
    uint32_t old_euid;
    uint32_t new_euid;
    uint64_t cap_effective;
    uint8_t  escalation;

    uint8_t  filename[128];
    uint8_t  sensitive;
    uint32_t flags;

    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t  proto;

    uint64_t addr;
    uint64_t length;
    uint32_t prot;
    uint32_t mmap_flags;
    uint8_t  rwx;
    uint8_t  anonymous;
};

typedef struct {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char     comm[16];
    uint64_t start_time_ns;
    uint64_t last_updated_ns;

    double   dim_score[KB_DIM_COUNT]; // dim_score[KB_DIM_SYSCALL] is the WINDOWED
                                       // (sliding) entropy — this is what drives
                                       // composite_score/ema_score/zone below.
    double   composite_score;
    double   ema_score;

    // Advisory only — does NOT feed composite_score/ema_score/zone.
    // Full-lifetime syscall-distribution entropy for this pid, for
    // audit/history purposes (e.g. "was this process ever unusual",
    // vs. dim_score[KB_DIM_SYSCALL]'s "is it unusual right now").
    double   syscall_entropy_lifetime;

    kb_zone_t zone;
    uint32_t  event_count;
    int       has_identity;  // true once comm/ppid/uid/start_time_ns are
                              // populated from a real kb_unified_event.
                              // MUST NOT be derived from event_count —
                              // kb_scoring_update_syscall_entropy() also
                              // increments event_count (via recompute()),
                              // and the entropy scan frequently creates a
                              // pid's slot before any real event does.
    int       in_use;
} kb_process_state_t;

typedef struct {
    kb_process_state_t *state;
    int        zone_changed;
    kb_zone_t  prev_zone;
} kb_scoring_result_t;

void kb_scoring_init(void);
kb_scoring_result_t kb_scoring_update(const struct kb_unified_event *evt);

// Feeds dim_score[KB_DIM_SYSCALL] — expects a WINDOWED (sliding, e.g.
// EMA-smoothed) entropy value, since this drives composite/zone and
// should reflect current behavior, not lifetime history.
kb_scoring_result_t kb_scoring_update_syscall_entropy(uint32_t pid, double entropy_0_100, uint64_t ts_ns);

// Sets syscall_entropy_lifetime only — no effect on composite/ema/zone.
// No-op if the pid isn't already tracked (call after
// kb_scoring_update_syscall_entropy for the same pid this scan, which
// creates the slot if needed).
void kb_scoring_set_syscall_entropy_lifetime(uint32_t pid, double entropy_0_100);

kb_process_state_t *kb_scoring_get_state(uint32_t pid);
void kb_scoring_remove(uint32_t pid);
const char *kb_zone_name(kb_zone_t z);

// /proc-backfill support. kb_scoring_update_syscall_entropy() alone can
// never populate comm/ppid/uid/start_time_ns for a pid that predates
// kbd_sensor's attach — no exec/exit/privilege/file/network/memory event
// ever fires for it, since it's already running. kb_scoring_has_identity()
// lets the caller check before doing the (more expensive) /proc read;
// kb_scoring_set_identity() is a no-op if identity is already set, so a
// later real kb_unified_event's data can never be clobbered by a stale
// /proc read racing behind it.
int  kb_scoring_has_identity(uint32_t pid);
void kb_scoring_set_identity(uint32_t pid, const char comm[16],
                              uint32_t ppid, uint32_t uid,
                              uint64_t start_time_ns);

#endif // KB_SCORING_H