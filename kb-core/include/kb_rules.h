// SPDX-License-Identifier: GPL-2.0
// KB Core — Attack Chain Rule Definitions
//
// Named attack patterns that the behavior engine recognizes.
// Each rule is a combination of:
//   - Required evidence flags (must ALL be set)
//   - Optional evidence flags (raise confidence if present)
//   - Sequence pattern (ordered event subsequence, if relevant)
//   - Time window (optional — e.g., all events within N nanoseconds)
//   - Target state (what state this rule can trigger)
//   - Reason code (why the transition happened)
//
// Adding new attack patterns: add a kb_attack_rule_t entry to the
// rules array in kb_rules.c. No other code needs to change.

#ifndef KB_RULES_H
#define KB_RULES_H

#include <stdint.h>
#include "kb_evidence.h"
#include "kb_behavior.h"

// ── Rule Structure ─────────────────────────────────────────────────────────
typedef struct {
    const char              *name;           // e.g. "reverse_shell"
    const char              *description;    // human-readable

    // Required evidence — ALL must be set to match
    uint64_t                 required_flags;

    // Optional evidence — each one present raises match confidence
    uint64_t                 optional_flags;
    int                      optional_min;   // min optional flags needed (0 = pure required)

    // Ordered sequence pattern — if non-NULL, must appear in evidence seq
    // (in order, not necessarily adjacent — subsequence match)
    const kb_ev_seq_entry_t *sequence;
    int                      sequence_len;

    // Time window constraint: if > 0, all required evidence must have been
    // observed within this window ending at current time.
    // 0 means no time constraint (lifetime evidence).
    uint64_t                 window_ns;

    // What state this rule can trigger (target state)
    kb_behavior_state_t      target_state;

    // Reason code and name emitted on match
    kb_transition_reason_t   reason;

    // Minimum source state for this rule to apply
    // e.g. BORDERLANDS→COMPROMISED rules only fire if already BORDERLANDS
    kb_behavior_state_t      min_source_state;

} kb_attack_rule_t;

#pragma pack(push, 1)
struct kb_wire_attack_rule {
    char                     name[32];
    char                     description[128];
    uint64_t                 required_flags;
    uint64_t                 optional_flags;
    int32_t                  optional_min;
    uint8_t                  sequence[16];
    int32_t                  sequence_len;
    uint64_t                 window_ns;
    uint32_t                 target_state;
    uint32_t                 reason;
    uint32_t                 min_source_state;
};
#pragma pack(pop)

// ── Rule Table API ─────────────────────────────────────────────────────────
// Returns pointer to the global rule table and its size.
const kb_attack_rule_t *kb_rules_get_table(int *out_count);

// Load dynamically sent rules from the Go Control Plane
void kb_rules_load_wire(const struct kb_wire_attack_rule *wire_rules, int count);

// Evaluate all rules against an evidence record.
// Returns the highest-priority matching rule, or NULL if no match.
// "Highest priority" = highest target_state among matches.
const kb_attack_rule_t *kb_rules_evaluate(const kb_evidence_t *ev,
                                            kb_behavior_state_t current_state,
                                            uint64_t now_ns);

#endif // KB_RULES_H