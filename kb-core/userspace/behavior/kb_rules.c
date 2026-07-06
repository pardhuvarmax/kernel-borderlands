// SPDX-License-Identifier: GPL-2.0
// KB Core — Attack Chain Rule Engine Implementation

#include <string.h>
#include <stdint.h>
#include "../../include/kb_rules.h"
#include "../../include/kb_evidence.h"
#include "../../include/kb_behavior.h"

// Defined sequence patterns
static const kb_ev_seq_entry_t seq_rev_shell[] = {
    KB_SEQ_OUTBOUND_CONNECT,
    KB_SEQ_EXEC_SHELL
};

static const kb_ev_seq_entry_t seq_injection_ptrace[] = {
    KB_SEQ_RWX_MAP,
    KB_SEQ_PTRACE
};

static const kb_ev_seq_entry_t seq_injection_proc_mem[] = {
    KB_SEQ_RWX_MAP,
    KB_SEQ_PROC_MEM_WRITE
};

static const kb_ev_seq_entry_t seq_ioc_chain[] = {
    KB_SEQ_EXEC,
    KB_SEQ_OUTBOUND_CONNECT,
    KB_SEQ_RWX_MAP
};

// Global rule table definition
static const kb_attack_rule_t rules_table[] = {
    // ── Direct/High Confidence Rules ──────────────────────────────────────────
    {
        .name = "known_ioc_sequence",
        .description = "Exact IOC sequence matched: exec -> outbound connect -> RWX memory",
        .required_flags = KB_EV_OUTBOUND_CONNECT | KB_EV_RWX_MAPPING,
        .optional_flags = KB_EV_EXEC_FROM_TMP | KB_EV_EXEC_FROM_PROC,
        .optional_min = 1,
        .sequence = seq_ioc_chain,
        .sequence_len = 3,
        .window_ns = 30000000000ULL, // 30 seconds
        .target_state = KB_STATE_COMPROMISED,
        .reason = KB_REASON_KNOWN_IOC_SEQUENCE,
        .min_source_state = KB_STATE_SAFE
    },

    // ── BORDERLANDS → COMPROMISED Rules ────────────────────────────────────────
    {
        .name = "reverse_shell_compromised",
        .description = "Outbound connection followed by shell execution",
        .required_flags = KB_EV_OUTBOUND_CONNECT | KB_EV_SPAWNED_SHELL,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = seq_rev_shell,
        .sequence_len = 2,
        .window_ns = 60000000000ULL, // 60 seconds
        .target_state = KB_STATE_COMPROMISED,
        .reason = KB_REASON_REVERSE_SHELL_CHAIN,
        .min_source_state = KB_STATE_BORDERLANDS
    },
    {
        .name = "injection_ptrace_compromised",
        .description = "RWX memory allocation followed by ptrace injection",
        .required_flags = KB_EV_RWX_MAPPING | KB_EV_PTRACE_USED,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = seq_injection_ptrace,
        .sequence_len = 2,
        .window_ns = 30000000000ULL, // 30 seconds
        .target_state = KB_STATE_COMPROMISED,
        .reason = KB_REASON_INJECTION_CHAIN,
        .min_source_state = KB_STATE_BORDERLANDS
    },
    {
        .name = "injection_proc_mem_compromised",
        .description = "RWX memory allocation followed by writing to proc memory",
        .required_flags = KB_EV_RWX_MAPPING | KB_EV_PROC_MEM_WRITE,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = seq_injection_proc_mem,
        .sequence_len = 2,
        .window_ns = 30000000000ULL, // 30 seconds
        .target_state = KB_STATE_COMPROMISED,
        .reason = KB_REASON_INJECTION_CHAIN,
        .min_source_state = KB_STATE_BORDERLANDS
    },
    {
        .name = "escalation_exfil_compromised",
        .description = "Privilege escalation followed by credential file access and outbound connection",
        .required_flags = KB_EV_PRIVILEGE_GAINED | KB_EV_OUTBOUND_CONNECT,
        .optional_flags = KB_EV_SHADOW_ACCESS | KB_EV_PASSWD_ACCESS | KB_EV_SSH_KEY_ACCESS,
        .optional_min = 1,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 120000000000ULL, // 120 seconds
        .target_state = KB_STATE_COMPROMISED,
        .reason = KB_REASON_ESCALATION_EXFIL_CHAIN,
        .min_source_state = KB_STATE_BORDERLANDS
    },

    // ── SUSPICIOUS → BORDERLANDS Rules ─────────────────────────────────────────
    {
        .name = "rwx_memory_abuse",
        .description = "RWX memory mapping or write to proc memory detected",
        .required_flags = 0,
        .optional_flags = KB_EV_RWX_MAPPING | KB_EV_PROC_MEM_WRITE | KB_EV_PROCESS_VM_WRITE,
        .optional_min = 1,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_BORDERLANDS,
        .reason = KB_REASON_RWX_MEMORY,
        .min_source_state = KB_STATE_SUSPICIOUS
    },
    {
        .name = "ptrace_injection_borderlands",
        .description = "Ptrace system call used by suspicious process",
        .required_flags = KB_EV_PTRACE_USED,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_BORDERLANDS,
        .reason = KB_REASON_PTRACE_INJECTION,
        .min_source_state = KB_STATE_SUSPICIOUS
    },
    {
        .name = "c2_port_connection",
        .description = "Outbound connection to suspected C2 port",
        .required_flags = KB_EV_OUTBOUND_CONNECT | KB_EV_C2_CANDIDATE_PORT,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_BORDERLANDS,
        .reason = KB_REASON_C2_PORT_CONNECT,
        .min_source_state = KB_STATE_SUSPICIOUS
    },
    {
        .name = "proc_mem_write_borderlands",
        .description = "Write to /proc/*/mem by suspicious process",
        .required_flags = KB_EV_PROC_MEM_WRITE,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_BORDERLANDS,
        .reason = KB_REASON_PROC_MEM_WRITE,
        .min_source_state = KB_STATE_SUSPICIOUS
    },
    {
        .name = "rapid_connect_burst_borderlands",
        .description = "Rapid connections to multiple distinct destination IPs",
        .required_flags = KB_EV_RAPID_CONNECT_BURST,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_BORDERLANDS,
        .reason = KB_REASON_RAPID_CONNECT_BURST,
        .min_source_state = KB_STATE_SUSPICIOUS
    },

    // ── OBSERVED → SUSPICIOUS Rules ────────────────────────────────────────────
    {
        .name = "multi_anomaly_suspicious",
        .description = "Multiple distinct behavioral anomaly categories set",
        .required_flags = 0,
        .optional_flags = (KB_EV_EXEC_FROM_TMP | KB_EV_EXEC_FROM_PROC | KB_EV_SPAWNED_SHELL |
                           KB_EV_PRIVILEGE_GAINED | KB_EV_ROOT_ACHIEVED |
                           KB_EV_RWX_MAPPING | KB_EV_ANON_EXEC | KB_EV_WX_TRANSITION |
                           KB_EV_OUTBOUND_CONNECT | KB_EV_NONSTANDARD_PORT |
                           KB_EV_SHADOW_ACCESS | KB_EV_SSH_KEY_ACCESS |
                           KB_EV_HIGH_SYSCALL_ENTROPY),
        .optional_min = 3,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_SUSPICIOUS,
        .reason = KB_REASON_MULTI_ANOMALY,
        .min_source_state = KB_STATE_OBSERVED
    },
    {
        .name = "privilege_plus_network_suspicious",
        .description = "Privilege change combined with outbound connection",
        .required_flags = KB_EV_PRIVILEGE_GAINED | KB_EV_OUTBOUND_CONNECT,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 60000000000ULL, // 60 seconds
        .target_state = KB_STATE_SUSPICIOUS,
        .reason = KB_REASON_PRIVILEGE_PLUS_NETWORK,
        .min_source_state = KB_STATE_OBSERVED
    },
    {
        .name = "cred_file_access_suspicious",
        .description = "Access to sensitive system credential stores",
        .required_flags = 0,
        .optional_flags = KB_EV_SHADOW_ACCESS | KB_EV_PASSWD_ACCESS | KB_EV_SUDOERS_ACCESS | KB_EV_SSH_KEY_ACCESS,
        .optional_min = 1,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_SUSPICIOUS,
        .reason = KB_REASON_CRED_FILE_ACCESS,
        .min_source_state = KB_STATE_OBSERVED
    },
    {
        .name = "anon_exec_mapping_suspicious",
        .description = "Anonymous executable memory mapping",
        .required_flags = KB_EV_ANON_EXEC,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_SUSPICIOUS,
        .reason = KB_REASON_ANON_EXEC_MAPPING,
        .min_source_state = KB_STATE_OBSERVED
    },
    {
        .name = "shell_spawn_suspicious",
        .description = "Unexpected shell spawn by anomalous process",
        .required_flags = KB_EV_SPAWNED_SHELL,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_SUSPICIOUS,
        .reason = KB_REASON_SHELL_SPAWN,
        .min_source_state = KB_STATE_OBSERVED
    },

    // ── SAFE → OBSERVED Rules ──────────────────────────────────────────────────
    {
        .name = "unexpected_outbound_connection",
        .description = "Any outbound connection",
        .required_flags = KB_EV_OUTBOUND_CONNECT,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_OBSERVED,
        .reason = KB_REASON_OUTBOUND_CONNECT,
        .min_source_state = KB_STATE_SAFE
    },
    {
        .name = "privilege_change_observed",
        .description = "Credential change (UID drop / Root achieved)",
        .required_flags = 0,
        .optional_flags = KB_EV_PRIVILEGE_GAINED | KB_EV_ROOT_ACHIEVED | KB_EV_CAP_GAINED,
        .optional_min = 1,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_OBSERVED,
        .reason = KB_REASON_PRIVILEGE_CHANGE,
        .min_source_state = KB_STATE_SAFE
    },
    {
        .name = "high_syscall_entropy_observed",
        .description = "Divergent syscall profile (high syscall entropy)",
        .required_flags = KB_EV_HIGH_SYSCALL_ENTROPY,
        .optional_flags = 0,
        .optional_min = 0,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_OBSERVED,
        .reason = KB_REASON_HIGH_SYSCALL_ENTROPY,
        .min_source_state = KB_STATE_SAFE
    },
    {
        .name = "first_anomaly_observed",
        .description = "Any initial anomaly flag set",
        .required_flags = 0,
        .optional_flags = 0xFFFFFFFFFFFFFFFFULL, // Match any flag
        .optional_min = 1,
        .sequence = NULL,
        .sequence_len = 0,
        .window_ns = 0,
        .target_state = KB_STATE_OBSERVED,
        .reason = KB_REASON_FIRST_ANOMALY,
        .min_source_state = KB_STATE_SAFE
    }
};

#define KB_MAX_DYNAMIC_RULES 128
static kb_attack_rule_t dynamic_rules_table[KB_MAX_DYNAMIC_RULES];
static int dynamic_rule_count = 0;
static int dynamic_rules_loaded = 0;

static char dynamic_names[KB_MAX_DYNAMIC_RULES][32];
static char dynamic_descriptions[KB_MAX_DYNAMIC_RULES][128];
static kb_ev_seq_entry_t dynamic_sequences[KB_MAX_DYNAMIC_RULES][16];

void kb_rules_load_wire(const struct kb_wire_attack_rule *wire_rules, int count)
{
    if (count > KB_MAX_DYNAMIC_RULES) count = KB_MAX_DYNAMIC_RULES;
    dynamic_rule_count = count;

    for (int i = 0; i < count; i++) {
        strncpy(dynamic_names[i], wire_rules[i].name, sizeof(dynamic_names[i]) - 1);
        dynamic_names[i][sizeof(dynamic_names[i]) - 1] = '\0';

        strncpy(dynamic_descriptions[i], wire_rules[i].description, sizeof(dynamic_descriptions[i]) - 1);
        dynamic_descriptions[i][sizeof(dynamic_descriptions[i]) - 1] = '\0';

        int seq_len = wire_rules[i].sequence_len;
        if (seq_len > 16) seq_len = 16;
        if (seq_len < 0) seq_len = 0;

        if (seq_len > 0) {
            memcpy(dynamic_sequences[i], wire_rules[i].sequence, seq_len);
            dynamic_rules_table[i].sequence = dynamic_sequences[i];
        } else {
            dynamic_rules_table[i].sequence = NULL;
        }
        dynamic_rules_table[i].sequence_len = seq_len;

        dynamic_rules_table[i].name = dynamic_names[i];
        dynamic_rules_table[i].description = dynamic_descriptions[i];
        dynamic_rules_table[i].required_flags = wire_rules[i].required_flags;
        dynamic_rules_table[i].optional_flags = wire_rules[i].optional_flags;
        dynamic_rules_table[i].optional_min = wire_rules[i].optional_min;
        dynamic_rules_table[i].window_ns = wire_rules[i].window_ns;
        dynamic_rules_table[i].target_state = (kb_behavior_state_t)wire_rules[i].target_state;
        dynamic_rules_table[i].reason = (kb_transition_reason_t)wire_rules[i].reason;
        dynamic_rules_table[i].min_source_state = (kb_behavior_state_t)wire_rules[i].min_source_state;
    }

    dynamic_rules_loaded = 1;
}

const kb_attack_rule_t *kb_rules_get_table(int *out_count)
{
    if (dynamic_rules_loaded) {
        if (out_count) {
            *out_count = dynamic_rule_count;
        }
        return dynamic_rules_table;
    }

    if (out_count) {
        *out_count = sizeof(rules_table) / sizeof(rules_table[0]);
    }
    return rules_table;
}

// Helper to count set bits in a 64-bit mask (popcount)
static inline int popcount64(uint64_t val)
{
    int count = 0;
    while (val) {
        count += (val & 1ULL);
        val >>= 1;
    }
    return count;
}

// Helper to verify time window constraints for a matched rule.
// We extract the first-observation times of the categories that contribute
// to the rule's active flags, and check if (max_t - min_t) <= window_ns.
static int verify_window_constraint(const kb_evidence_t *ev, const kb_attack_rule_t *rule)
{
    if (rule->window_ns == 0)
        return 1;

    uint64_t times[5];
    int count = 0;
    uint64_t mask = rule->required_flags | (ev->flags & rule->optional_flags);

    // Exec category
    if (mask & (KB_EV_EXEC_FROM_TMP | KB_EV_EXEC_FROM_PROC | KB_EV_SPAWNED_SHELL | KB_EV_RAPID_EXEC_BURST)) {
        if (ev->first_exec_ns > 0) {
            times[count++] = ev->first_exec_ns;
        }
    }
    // Privilege category
    if (mask & (KB_EV_PRIVILEGE_GAINED | KB_EV_ROOT_ACHIEVED | KB_EV_CAP_GAINED | KB_EV_SETUID_ABUSE)) {
        if (ev->first_privilege_ns > 0) {
            times[count++] = ev->first_privilege_ns;
        }
    }
    // Memory category
    if (mask & (KB_EV_RWX_MAPPING | KB_EV_ANON_EXEC | KB_EV_WX_TRANSITION | KB_EV_PROC_MEM_WRITE | KB_EV_PROCESS_VM_WRITE)) {
        if (ev->first_rwx_ns > 0) {
            times[count++] = ev->first_rwx_ns;
        }
    }
    // Network category
    if (mask & (KB_EV_OUTBOUND_CONNECT | KB_EV_NONSTANDARD_PORT | KB_EV_C2_CANDIDATE_PORT | KB_EV_BIND_LISTENER)) {
        if (ev->first_network_ns > 0) {
            times[count++] = ev->first_network_ns;
        }
    }
    // Credential file category
    if (mask & (KB_EV_SHADOW_ACCESS | KB_EV_PASSWD_ACCESS | KB_EV_SUDOERS_ACCESS | KB_EV_SSH_KEY_ACCESS)) {
        if (ev->first_cred_file_ns > 0) {
            times[count++] = ev->first_cred_file_ns;
        }
    }

    if (count <= 1)
        return 1; // 0 or 1 category active: trivially satisfies window constraint

    uint64_t min_t = times[0];
    uint64_t max_t = times[0];
    for (int i = 1; i < count; i++) {
        if (times[i] < min_t) min_t = times[i];
        if (times[i] > max_t) max_t = times[i];
    }

    return (max_t - min_t) <= rule->window_ns;
}

const kb_attack_rule_t *kb_rules_evaluate(const kb_evidence_t *ev,
                                           kb_behavior_state_t current_state,
                                           uint64_t now_ns)
{
    if (!ev) return NULL;

    int rule_count = 0;
    const kb_attack_rule_t *rules = kb_rules_get_table(&rule_count);
    const kb_attack_rule_t *best_match = NULL;

    for (int i = 0; i < rule_count; i++) {
        const kb_attack_rule_t *rule = &rules[i];

        // 1. Minimum source state constraint
        if (current_state < rule->min_source_state)
            continue;

        // 2. Already at or past target state: no need to fire this rule unless it escalates
        if (current_state >= rule->target_state)
            continue;

        // 3. Required flags check
        if (rule->required_flags && !kb_evidence_has_all(ev, rule->required_flags))
            continue;

        // 4. Optional flags check
        if (rule->optional_flags) {
            uint64_t matched_opts = ev->flags & rule->optional_flags;
            if (popcount64(matched_opts) < rule->optional_min)
                continue;
        }

        // 5. Sequence constraint check
        if (rule->sequence && rule->sequence_len > 0) {
            if (!kb_evidence_seq_contains(ev, rule->sequence, rule->sequence_len))
                continue;
        }

        // 6. Time window check
        if (!verify_window_constraint(ev, rule))
            continue;

        // Found a matching rule! Select the one with the highest target_state.
        if (!best_match || rule->target_state > best_match->target_state) {
            best_match = rule;
        }
    }

    return best_match;
}
