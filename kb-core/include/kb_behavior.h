// SPDX-License-Identifier: GPL-2.0
// KB Core — Behavioral State Machine
//
// Replaces weighted-score classification as the DECISION ENGINE.
// The scoring engine (kb_scoring.c) remains but is demoted to advisory/dashboard.
//
// State transitions are driven by evidence + sequence pattern matching,
// not by crossing numeric thresholds. This makes the engine:
//   - Harder to evade (can't decay a score by pausing activity)
//   - More explainable (transitions have named reasons)
//   - More accurate (catches attack chains, not isolated events)
//   - Sequence-aware (order of events matters)
//
// See: docs/ADR-002-behavior-engine.md

#ifndef KB_BEHAVIOR_H
#define KB_BEHAVIOR_H

#include <stdint.h>
#include "kb_evidence.h"

// ── Behavioral States ─────────────────────────────────────────────────────
// States are strictly ordered: a process can only move forward (escalate)
// or to RECOVERING (de-escalate after CONTAINED). It cannot jump steps.
// Exception: direct SAFE→COMPROMISED is possible for high-confidence chains.

typedef enum {
    KB_STATE_SAFE        = 0,  // No unusual activity
    KB_STATE_OBSERVED    = 1,  // Minor anomaly noticed — watching
    KB_STATE_SUSPICIOUS  = 2,  // Multiple anomalies — elevated monitoring
    KB_STATE_BORDERLANDS = 3,  // Active threat indicators — containment applied
    KB_STATE_COMPROMISED = 4,  // High-confidence attack chain confirmed
    KB_STATE_CONTAINED   = 5,  // Enforcement active (cgroup/seccomp/namespace)
    KB_STATE_RECOVERING  = 6,  // Score normalizing — monitoring relaxation
} kb_behavior_state_t;

// ── Transition Reason ─────────────────────────────────────────────────────
// Every state transition carries a human-readable reason.
// Reason is logged to audit trail and sent to Control Plane.
// This makes the system explainable to operators.

typedef enum {
    KB_REASON_NONE                      = 0,

    // SAFE → OBSERVED
    KB_REASON_FIRST_ANOMALY             = 1,   // first unusual event observed
    KB_REASON_OUTBOUND_CONNECT          = 2,   // unexpected outbound connection
    KB_REASON_PRIVILEGE_CHANGE          = 3,   // credential change observed
    KB_REASON_HIGH_SYSCALL_ENTROPY      = 4,   // syscall distribution diverging

    // OBSERVED → SUSPICIOUS
    KB_REASON_MULTI_ANOMALY             = 10,  // 3+ distinct anomaly types
    KB_REASON_PRIVILEGE_PLUS_NETWORK    = 11,  // escalation + outbound
    KB_REASON_CRED_FILE_ACCESS          = 12,  // credential file touched
    KB_REASON_ANON_EXEC_MAPPING         = 13,  // anonymous executable memory
    KB_REASON_SHELL_SPAWN               = 14,  // unexpected shell spawn

    // SUSPICIOUS → BORDERLANDS
    KB_REASON_RWX_MEMORY                = 20,  // RWX mapping present
    KB_REASON_ATTACK_CHAIN_PARTIAL      = 21,  // partial known attack pattern
    KB_REASON_PTRACE_INJECTION          = 22,  // ptrace on another process
    KB_REASON_C2_PORT_CONNECT           = 23,  // connected to C2 candidate port
    KB_REASON_PROC_MEM_WRITE            = 24,  // wrote to /proc/*/mem
    KB_REASON_RAPID_CONNECT_BURST       = 25,  // scanning/beacon behavior

    // BORDERLANDS → COMPROMISED
    KB_REASON_REVERSE_SHELL_CHAIN       = 30,  // socket+dup2+exec(/bin/sh)
    KB_REASON_INJECTION_CHAIN           = 31,  // RWX+ptrace or proc/mem write
    KB_REASON_ESCALATION_EXFIL_CHAIN    = 32,  // privilege+cred+network
    KB_REASON_FULL_ATTACK_CHAIN         = 33,  // complete known attack sequence

    // Direct (any state → COMPROMISED, high confidence only)
    KB_REASON_KNOWN_IOC_SEQUENCE        = 40,  // exact IOC sequence match

    // De-escalation
    KB_REASON_EVIDENCE_INSUFFICIENT     = 50,  // false positive — relax
    KB_REASON_OPERATOR_OVERRIDE         = 51,  // human cleared the process
} kb_transition_reason_t;

// ── State Machine Record (per process) ────────────────────────────────────
typedef struct {
    uint32_t             pid;
    uint32_t             ppid;
    char                 comm[16];
    uint64_t             start_time_ns;

    kb_behavior_state_t  state;
    kb_behavior_state_t  prev_state;
    kb_transition_reason_t last_reason;

    uint64_t             state_entered_ns;   // when did we enter current state
    uint64_t             last_evaluated_ns;  // last time rules were evaluated

    // Count of distinct evidence types (not total events — distinct flags set)
    int                  distinct_evidence_count;

    // Advisory score (from kb_scoring.c — kept for dashboard, not decisions)
    double               advisory_ema;

    int                  in_use;
} kb_behavior_record_t;

// ── Transition Result ─────────────────────────────────────────────────────
typedef struct {
    kb_behavior_record_t *record;
    int                   state_changed;
    kb_behavior_state_t   prev_state;
    kb_behavior_state_t   new_state;
    kb_transition_reason_t reason;
    const char           *reason_str;   // human-readable
    const char           *chain_name;   // if a named attack chain matched, its name
} kb_behavior_result_t;

// ── Behavior Engine API ───────────────────────────────────────────────────
#define KB_BEHAVIOR_MAX_PROCS 10240

void kb_behavior_init(void);

// Primary entry point: evaluate evidence for a process and return transition result.
// Called after kb_evidence_set_flag() / kb_evidence_push_seq() update the evidence.
// This is what replaces kb_scoring_update() as the enforcement decision trigger.
kb_behavior_result_t kb_behavior_evaluate(const kb_evidence_t *ev);

// Get or create a behavior record for a process.
kb_behavior_record_t *kb_behavior_get(uint32_t pid);
void                  kb_behavior_remove(uint32_t pid);

// Human-readable names
const char *kb_state_name(kb_behavior_state_t s);
const char *kb_reason_name(kb_transition_reason_t r);

#endif // KB_BEHAVIOR_H