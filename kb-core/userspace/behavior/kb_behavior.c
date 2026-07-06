// SPDX-License-Identifier: GPL-2.0
// KB Core — Behavioral State Machine Implementation

#include <string.h>
#include <stdint.h>
#include <time.h>
#include "../../include/kb_behavior.h"
#include "../../include/kb_evidence.h"
#include "../../include/kb_rules.h"

// Per-process behavior record store (open-addressing hash table)
static kb_behavior_record_t behavior_table[KB_BEHAVIOR_MAX_PROCS];

void kb_behavior_init(void)
{
    memset(behavior_table, 0, sizeof(behavior_table));
}

static uint32_t behavior_slot(uint32_t pid)
{
    return pid % KB_BEHAVIOR_MAX_PROCS;
}

kb_behavior_record_t *kb_behavior_get(uint32_t pid)
{
    uint32_t idx = behavior_slot(pid);
    for (uint32_t i = 0; i < KB_BEHAVIOR_MAX_PROCS; i++) {
        uint32_t s = (idx + i) % KB_BEHAVIOR_MAX_PROCS;
        if (behavior_table[s].in_use && behavior_table[s].pid == pid)
            return &behavior_table[s];
        if (!behavior_table[s].in_use)
            return NULL;
    }
    return NULL;
}

static kb_behavior_record_t *kb_behavior_get_or_create(uint32_t pid, uint32_t ppid,
                                                       const char *comm, uint64_t start_time_ns)
{
    uint32_t idx = behavior_slot(pid);
    for (uint32_t i = 0; i < KB_BEHAVIOR_MAX_PROCS; i++) {
        uint32_t s = (idx + i) % KB_BEHAVIOR_MAX_PROCS;
        if (behavior_table[s].in_use && behavior_table[s].pid == pid)
            return &behavior_table[s];
        if (!behavior_table[s].in_use) {
            memset(&behavior_table[s], 0, sizeof(kb_behavior_record_t));
            behavior_table[s].pid = pid;
            behavior_table[s].ppid = ppid;
            behavior_table[s].start_time_ns = start_time_ns;
            behavior_table[s].state = KB_STATE_SAFE;
            behavior_table[s].in_use = 1;
            if (comm) {
                strncpy(behavior_table[s].comm, comm, sizeof(behavior_table[s].comm) - 1);
            }
            return &behavior_table[s];
        }
    }
    return NULL; // table full
}

void kb_behavior_remove(uint32_t pid)
{
    kb_behavior_record_t *rec = kb_behavior_get(pid);
    if (rec) {
        rec->in_use = 0;
    }
}

kb_behavior_result_t kb_behavior_evaluate(const kb_evidence_t *ev)
{
    kb_behavior_result_t result = {0};
    if (!ev) return result;

    kb_behavior_record_t *rec = kb_behavior_get_or_create(ev->pid, ev->ppid, ev->comm, ev->start_time_ns);
    if (!rec) return result;

    // Sync metadata from evidence record
    if (ev->comm[0] != '\0' && rec->comm[0] == '\0') {
        strncpy(rec->comm, ev->comm, sizeof(rec->comm) - 1);
    }
    if (ev->ppid > 0) {
        rec->ppid = ev->ppid;
    }
    if (ev->start_time_ns > 0) {
        rec->start_time_ns = ev->start_time_ns;
    }

    // Count distinct evidence types (non-zero bits in flags)
    int distinct_count = 0;
    uint64_t temp_flags = ev->flags;
    while (temp_flags) {
        distinct_count += (int)(temp_flags & 1ULL);
        temp_flags >>= 1;
    }
    rec->distinct_evidence_count = distinct_count;

    // Sync advisory EMA
    rec->advisory_ema = ev->advisory_ema;

    // Determine current time
    uint64_t now = ev->last_exec_ns;
    if (now == 0) now = ev->last_connect_ns;
    if (now == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }

    // Evaluate rules
    const kb_attack_rule_t *matched_rule = kb_rules_evaluate(ev, rec->state, now);

    if (matched_rule) {
        kb_behavior_state_t prev = rec->state;
        kb_behavior_state_t next = matched_rule->target_state;

        // Safety clamp: prevent state jumps (unless to COMPROMISED)
        if (next > prev + 1 && next != KB_STATE_COMPROMISED) {
            next = prev + 1;
        }

        if (next != prev) {
            rec->prev_state = prev;
            rec->state = next;
            rec->last_reason = matched_rule->reason;
            rec->state_entered_ns = now;

            result.state_changed = 1;
            result.prev_state = prev;
            result.new_state = next;
            result.reason = matched_rule->reason;
            result.reason_str = kb_reason_name(matched_rule->reason);
            result.chain_name = matched_rule->name;
        }
    }

    rec->last_evaluated_ns = now;
    result.record = rec;
    return result;
}

const char *kb_state_name(kb_behavior_state_t s)
{
    switch (s) {
        case KB_STATE_SAFE:        return "SAFE";
        case KB_STATE_OBSERVED:    return "OBSERVED";
        case KB_STATE_SUSPICIOUS:  return "SUSPICIOUS";
        case KB_STATE_BORDERLANDS: return "BORDERLANDS";
        case KB_STATE_COMPROMISED: return "COMPROMISED";
        case KB_STATE_CONTAINED:   return "CONTAINED";
        case KB_STATE_RECOVERING:  return "RECOVERING";
        default:                   return "UNKNOWN";
    }
}

const char *kb_reason_name(kb_transition_reason_t r)
{
    switch (r) {
        case KB_REASON_NONE:                   return "NONE";
        case KB_REASON_FIRST_ANOMALY:          return "FIRST_ANOMALY";
        case KB_REASON_OUTBOUND_CONNECT:       return "OUTBOUND_CONNECT";
        case KB_REASON_PRIVILEGE_CHANGE:       return "PRIVILEGE_CHANGE";
        case KB_REASON_HIGH_SYSCALL_ENTROPY:   return "HIGH_SYSCALL_ENTROPY";
        case KB_REASON_MULTI_ANOMALY:          return "MULTI_ANOMALY";
        case KB_REASON_PRIVILEGE_PLUS_NETWORK: return "PRIVILEGE_PLUS_NETWORK";
        case KB_REASON_CRED_FILE_ACCESS:       return "CRED_FILE_ACCESS";
        case KB_REASON_ANON_EXEC_MAPPING:      return "ANON_EXEC_MAPPING";
        case KB_REASON_SHELL_SPAWN:            return "SHELL_SPAWN";
        case KB_REASON_RWX_MEMORY:             return "RWX_MEMORY";
        case KB_REASON_ATTACK_CHAIN_PARTIAL:   return "ATTACK_CHAIN_PARTIAL";
        case KB_REASON_PTRACE_INJECTION:       return "PTRACE_INJECTION";
        case KB_REASON_C2_PORT_CONNECT:        return "C2_PORT_CONNECT";
        case KB_REASON_PROC_MEM_WRITE:         return "PROC_MEM_WRITE";
        case KB_REASON_RAPID_CONNECT_BURST:    return "RAPID_CONNECT_BURST";
        case KB_REASON_REVERSE_SHELL_CHAIN:    return "REVERSE_SHELL_CHAIN";
        case KB_REASON_INJECTION_CHAIN:        return "INJECTION_CHAIN";
        case KB_REASON_ESCALATION_EXFIL_CHAIN: return "ESCALATION_EXFIL_CHAIN";
        case KB_REASON_FULL_ATTACK_CHAIN:      return "FULL_ATTACK_CHAIN";
        case KB_REASON_KNOWN_IOC_SEQUENCE:     return "KNOWN_IOC_SEQUENCE";
        case KB_REASON_EVIDENCE_INSUFFICIENT:  return "EVIDENCE_INSUFFICIENT";
        case KB_REASON_OPERATOR_OVERRIDE:      return "OPERATOR_OVERRIDE";
        default:                               return "UNKNOWN_REASON";
    }
}
