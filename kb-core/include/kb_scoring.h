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

// Dimension weights sum to 1.0 — values taken from the "Weight: N%"
// comments already present in each ebpf/kb_*.bpf.c header.
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

// Event type codes — must match kbd_sensor.c's KB_EVT_* defines exactly.
#define KB_EVT_PROCESS_EXEC      0
#define KB_EVT_PROCESS_EXIT      1
#define KB_EVT_SYSCALL           2
#define KB_EVT_PRIVILEGE_CHANGE  3
#define KB_EVT_FILE_ACCESS       4
#define KB_EVT_NETWORK_CONNECT   5
#define KB_EVT_NETWORK_BIND      6
#define KB_EVT_MEMORY_MMAP       7
#define KB_EVT_MEMORY_MPROTECT   8

// Mirrors struct kb_unified_event in userspace/sensor/kbd_sensor.c.
// Kept as a separate definition (not shared via a common header) is a
// known wart — worth moving both to one shared header once this compiles.
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

    uint64_t start_time_ns;   // ts of first event seen for this pid —
                               // PID-reuse guard for the enforcement side
    uint64_t last_updated_ns;

    double   dim_score[KB_DIM_COUNT]; // latest raw 0-100 score per dimension
    double   composite_score;         // weighted sum of dim_score
    double   ema_score;                // EMA of composite_score over time

    kb_zone_t zone;
    uint32_t  event_count;
    int       in_use;
} kb_process_state_t;

// Result of feeding one event in — the bridge reads zone_changed to
// decide whether a ZoneTransition message needs to go out now, vs.
// just letting the state ride in the next periodic ProcessState sync.
typedef struct {
    kb_process_state_t *state;
    int        zone_changed;
    kb_zone_t  prev_zone;
} kb_scoring_result_t;

void kb_scoring_init(void);

// Feed one kb_unified_event into the engine. Handles process_exit
// internally (removes the pid from the table after scoring the exit).
kb_scoring_result_t kb_scoring_update(const struct kb_unified_event *evt);

// Separate path for the syscall dimension — see note in kb_scoring.c
// on why this can't come from kb_unified_event. entropy expected as
// a 0-100 normalized score, already computed by the caller from
// kb_syscall_counts / kb_syscall_totals.
kb_scoring_result_t kb_scoring_update_syscall_entropy(uint32_t pid, double entropy_0_100);

kb_process_state_t *kb_scoring_get_state(uint32_t pid);
void kb_scoring_remove(uint32_t pid);
const char *kb_zone_name(kb_zone_t z);

#endif // KB_SCORING_H