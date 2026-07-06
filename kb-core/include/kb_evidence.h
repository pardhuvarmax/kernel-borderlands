// SPDX-License-Identifier: GPL-2.0
// KB Core — Evidence Accumulator
//
// Each process accumulates a set of behavioral evidence flags.
// Evidence is NEVER cleared during a process lifetime — it's append-only.
// The behavior engine reasons over accumulated evidence + sequence, not scores.
//
// Design rationale: an attacker can momentarily stop doing something suspicious
// to let a score decay. They cannot un-do that they already RWX-mapped memory.

#ifndef KB_EVIDENCE_H
#define KB_EVIDENCE_H

#include <stdint.h>
#include <stddef.h>

// ── Evidence flags (bitmask, 64-bit) ──────────────────────────────────────
// Each flag represents a behavioral observation that happened at least once.
// Flags are set, never cleared. Reasoning: if a process did it, it did it.

#define KB_EV_NONE                    0ULL

// Process & Execution
#define KB_EV_EXEC_FROM_TMP           (1ULL << 0)  // execve from /tmp or /dev/shm
#define KB_EV_EXEC_FROM_PROC          (1ULL << 1)  // execve from /proc/*/fd (memfd)
#define KB_EV_SPAWNED_SHELL           (1ULL << 2)  // exec'd sh/bash/zsh/dash/fish
#define KB_EV_ANOMALOUS_PARENT        (1ULL << 3)  // parent unusual for this comm
#define KB_EV_RAPID_EXEC_BURST        (1ULL << 4)  // >10 exec events in 5 seconds
#define KB_EV_EXECVEAT                (1ULL << 5)  // used execveat() (fd-based exec)

// Privilege & Credentials
#define KB_EV_PRIVILEGE_GAINED        (1ULL << 8)  // uid/euid dropped toward 0
#define KB_EV_ROOT_ACHIEVED           (1ULL << 9)  // euid became 0
#define KB_EV_CAP_GAINED              (1ULL << 10) // capability set expanded
#define KB_EV_SETUID_ABUSE            (1ULL << 11) // setuid called post-network

// Memory
#define KB_EV_RWX_MAPPING             (1ULL << 16) // mmap(PROT_READ|WRITE|EXEC)
#define KB_EV_ANON_EXEC               (1ULL << 17) // anonymous executable mapping
#define KB_EV_WX_TRANSITION           (1ULL << 18) // mprotect W→X (write then exec)
#define KB_EV_LARGE_ANON_EXEC         (1ULL << 19) // anon exec mapping > 1MB
#define KB_EV_PROC_MEM_WRITE          (1ULL << 20) // write to /proc/*/mem
#define KB_EV_PROCESS_VM_WRITE        (1ULL << 21) // process_vm_writev() used

// File & Credential Files
#define KB_EV_SHADOW_ACCESS           (1ULL << 24) // /etc/shadow opened
#define KB_EV_PASSWD_ACCESS           (1ULL << 25) // /etc/passwd opened
#define KB_EV_SUDOERS_ACCESS          (1ULL << 26) // /etc/sudoers opened
#define KB_EV_SSH_KEY_ACCESS          (1ULL << 27) // ~/.ssh/ or /root/.ssh/ opened
#define KB_EV_CRON_WRITE              (1ULL << 28) // crontab or /etc/cron* written
#define KB_EV_BINARY_PATH_WRITE       (1ULL << 29) // write to /bin /usr/bin /sbin

// Network
#define KB_EV_OUTBOUND_CONNECT        (1ULL << 32) // any outbound connect()
#define KB_EV_NONSTANDARD_PORT        (1ULL << 33) // connect to port outside 80/443/22/53
#define KB_EV_C2_CANDIDATE_PORT       (1ULL << 34) // port in common C2 list (4444,1337,etc)
#define KB_EV_BIND_LISTENER           (1ULL << 35) // bind() + listen() by non-server process
#define KB_EV_DNS_TUNNEL_SUSPECT      (1ULL << 36) // high-entropy DNS queries
#define KB_EV_RAPID_CONNECT_BURST     (1ULL << 37) // >5 distinct IPs in 10 seconds

// Syscall Behavior
#define KB_EV_HIGH_SYSCALL_ENTROPY    (1ULL << 40) // KL divergence > threshold
#define KB_EV_PTRACE_USED             (1ULL << 41) // ptrace() called
#define KB_EV_SECCOMP_BYPASS_ATTEMPT  (1ULL << 42) // syscall after seccomp filter
#define KB_EV_UNUSUAL_SYSCALL_SEQ     (1ULL << 43) // sequence matches shellcode pattern

// ── Evidence sequence (ordered, bounded ring buffer) ──────────────────────
// Stores the last KB_EVIDENCE_SEQ_LEN event types seen, in order.
// Used by the pattern matcher for temporal/sequential reasoning.
// This is what catches "exec → network → RWX" as distinct from "RWX → exec".

#define KB_EVIDENCE_SEQ_LEN  32

typedef uint8_t kb_ev_seq_entry_t;

// Sequence entry event codes (compact, separate from flag bits)
typedef enum {
    KB_SEQ_NONE              = 0,
    KB_SEQ_EXEC              = 1,
    KB_SEQ_EXEC_SHELL        = 2,
    KB_SEQ_EXIT              = 3,
    KB_SEQ_PRIVILEGE_UP      = 4,
    KB_SEQ_PRIVILEGE_ROOT    = 5,
    KB_SEQ_RWX_MAP           = 6,
    KB_SEQ_ANON_EXEC         = 7,
    KB_SEQ_WX_TRANSITION     = 8,
    KB_SEQ_SHADOW_ACCESS     = 9,
    KB_SEQ_SSH_KEY_ACCESS    = 10,
    KB_SEQ_OUTBOUND_CONNECT  = 11,
    KB_SEQ_NONSTD_PORT       = 12,
    KB_SEQ_C2_PORT           = 13,
    KB_SEQ_BIND_LISTEN       = 14,
    KB_SEQ_HIGH_ENTROPY      = 15,
    KB_SEQ_PTRACE            = 16,
    KB_SEQ_PROC_MEM_WRITE    = 17,
    KB_SEQ_CRED_FILE         = 18,
    KB_SEQ_RAPID_EXEC        = 19,
    KB_SEQ_RAPID_CONNECT     = 20,
} kb_seq_event_t;

// ── Per-process evidence record ────────────────────────────────────────────
typedef struct {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char     comm[16];
    uint64_t start_time_ns;

    // Bitmask: all evidence ever observed (never cleared)
    uint64_t flags;

    // Time of first observation per evidence category
    uint64_t first_exec_ns;
    uint64_t first_privilege_ns;
    uint64_t first_rwx_ns;
    uint64_t first_network_ns;
    uint64_t first_cred_file_ns;

    // Sequence ring buffer (ordered history of event types)
    kb_ev_seq_entry_t seq[KB_EVIDENCE_SEQ_LEN];
    uint8_t           seq_head;   // next write position (wraps)
    uint8_t           seq_len;    // how many entries are valid (max KB_EVIDENCE_SEQ_LEN)

    // Counters (NOT used for scoring — used for burst/rate detection)
    uint32_t exec_count;
    uint32_t connect_count;
    uint32_t distinct_ip_count;
    uint32_t rwx_map_count;
    uint32_t cred_file_count;

    // Last event timestamp (for burst detection window)
    uint64_t last_exec_ns;
    uint64_t last_connect_ns;

    // Advisory: EMA score (kept for dashboard/trends, not for state decisions)
    double   advisory_ema;
    double   advisory_composite;

    int      in_use;
} kb_evidence_t;

// ── Evidence store API ────────────────────────────────────────────────────
#define KB_EVIDENCE_MAX_PROCS 10240

void         kb_evidence_init(void);
kb_evidence_t *kb_evidence_get(uint32_t pid);
kb_evidence_t *kb_evidence_get_or_create(uint32_t pid, uint32_t ppid,
                                          uint32_t uid, const char *comm,
                                          uint64_t start_time_ns);
void         kb_evidence_remove(uint32_t pid);

// Set an evidence flag (idempotent — safe to call multiple times)
void         kb_evidence_set_flag(kb_evidence_t *ev, uint64_t flag, uint64_t ts_ns);

// Append to the ordered sequence buffer
void         kb_evidence_push_seq(kb_evidence_t *ev, kb_seq_event_t entry);

// Check if a flag is set
static inline int kb_evidence_has(const kb_evidence_t *ev, uint64_t flag) {
    return (ev->flags & flag) != 0;
}

// Check if ALL flags in mask are set
static inline int kb_evidence_has_all(const kb_evidence_t *ev, uint64_t mask) {
    return (ev->flags & mask) == mask;
}

// Check if ANY flag in mask is set
static inline int kb_evidence_has_any(const kb_evidence_t *ev, uint64_t mask) {
    return (ev->flags & mask) != 0;
}

// Iterate the sequence buffer in chronological order.
// Returns the number of valid entries copied into out_buf (max out_len).
int kb_evidence_get_seq(const kb_evidence_t *ev,
                         kb_ev_seq_entry_t *out_buf, int out_len);

// Check if a subsequence appears in the evidence sequence (in order, not necessarily adjacent)
// Returns 1 if found, 0 if not.
int kb_evidence_seq_contains(const kb_evidence_t *ev,
                               const kb_ev_seq_entry_t *pattern, int pattern_len);

#endif // KB_EVIDENCE_H