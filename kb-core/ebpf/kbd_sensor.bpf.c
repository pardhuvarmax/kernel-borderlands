// SPDX-License-Identifier: GPL-2.0
// KB Core — Unified Sensor
// Combines all 6 hook points into a single eBPF object,
// emitting a unified kb_unified_event into ONE ring buffer.
//
// This is the actual sensor that feeds the Control Plane.
// Individual hook binaries (kb_process, kb_syscall, etc.)
// remain useful for isolated testing/debugging.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define KB_MAX_PROCESSES 10240

// ── Unified event types (locked contract — see docs/event-contract.md) ──
#define KB_EVT_PROCESS_EXEC      0
#define KB_EVT_PROCESS_EXIT      1
#define KB_EVT_SYSCALL           2
#define KB_EVT_PRIVILEGE_CHANGE  3
#define KB_EVT_FILE_ACCESS       4
#define KB_EVT_NETWORK_CONNECT   5
#define KB_EVT_NETWORK_BIND      6
#define KB_EVT_MEMORY_MMAP       7
#define KB_EVT_MEMORY_MPROTECT   8

// ── Single unified event struct — matches across ALL hooks ──
// metadata fields are reused per event_type per the locked contract.
// Unused fields for a given event_type are simply left as 0.
struct kb_unified_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8  comm[16];
    __u8  event_type;
    __u64 ts_ns;

    // syscall
    __u32 syscall_nr;

    // privilege_change
    __u32 old_uid;
    __u32 new_uid;
    __u32 old_euid;
    __u32 new_euid;
    __u64 cap_effective;
    __u8  escalation;

    // file_access
    __u8  filename[128];
    __u8  sensitive;
    __u32 flags;

    // network_connect / network_bind
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;

    // memory_mmap / memory_mprotect
    __u64 addr;
    __u64 length;
    __u32 prot;
    __u32 mmap_flags;
    __u8  rwx;
    __u8  anonymous;
};

// ── ONE ring buffer for everything ──
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1MB, shared across all hooks
} kb_events SEC(".maps");

// ── Supporting state maps (carried over from individual hooks) ──
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KB_MAX_PROCESSES);
    __type(key,   __u32);
    __type(value, __u64);
} kb_syscall_totals SEC(".maps");

struct kb_cred_snapshot {
    __u32 uid;
    __u32 gid;
    __u32 euid;
    __u64 cap_effective;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KB_MAX_PROCESSES);
    __type(key,   __u32);
    __type(value, struct kb_cred_snapshot);
} kb_cred_prev SEC(".maps");

// ── Helper: reserve + zero a unified event ──
static __always_inline struct kb_unified_event *kb_reserve_event(void)
{
    struct kb_unified_event *e =
        bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
    if (!e)
        return NULL;
    __builtin_memset(e, 0, sizeof(*e));
    return e;
}

static __always_inline void kb_fill_common(
    struct kb_unified_event *e, __u32 pid, __u8 event_type)
{
    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    e->pid        = pid;
    e->ppid       = BPF_CORE_READ(task, real_parent, tgid);
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->event_type = event_type;
    e->ts_ns      = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// ═══════════════════════════════════════════════════════════
// HOOK 1 — Process Lifecycle
// ═══════════════════════════════════════════════════════════

SEC("tp/sched/sched_process_exec")
int kb_handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e)
        return 0;

    kb_fill_common(e, pid, KB_EVT_PROCESS_EXEC);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int kb_handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e)
        return 0;

    kb_fill_common(e, pid, KB_EVT_PROCESS_EXIT);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════
// HOOK 2 — Syscall Entropy (sampled every 100 syscalls)
// ═══════════════════════════════════════════════════════════

SEC("tracepoint/raw_syscalls/sys_enter")
int kb_handle_syscall(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    long  syscall_nr = ctx->id;

    if (pid == 0 || syscall_nr < 0 || pid != tid)
        return 0;

    __u64 *total = bpf_map_lookup_elem(&kb_syscall_totals, &pid);
    if (total) {
        __sync_fetch_and_add(total, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&kb_syscall_totals, &pid, &one, BPF_ANY);
    }

    __u64 *t = bpf_map_lookup_elem(&kb_syscall_totals, &pid);
    if (!t || (*t % 100 != 0))
        return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e)
        return 0;

    kb_fill_common(e, pid, KB_EVT_SYSCALL);
    e->syscall_nr = (__u32)syscall_nr;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════
// HOOK 3 — Privilege Change
// ═══════════════════════════════════════════════════════════

SEC("kprobe/commit_creds")
int kb_handle_commit_creds(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    struct cred *new_cred = (struct cred *)PT_REGS_PARM1(ctx);
    if (!new_cred)
        return 0;

    __u32 new_uid  = BPF_CORE_READ(new_cred, uid.val);
    __u32 new_euid = BPF_CORE_READ(new_cred, euid.val);
    __u64 new_cap  = BPF_CORE_READ(new_cred, cap_effective.val);

    struct kb_cred_snapshot *prev =
        bpf_map_lookup_elem(&kb_cred_prev, &pid);

    __u32 old_uid  = prev ? prev->uid  : new_uid;
    __u32 old_euid = prev ? prev->euid : new_euid;
    __u64 old_cap  = prev ? prev->cap_effective : new_cap;

    struct kb_cred_snapshot snap = {
        .uid = new_uid, .euid = new_euid, .cap_effective = new_cap
    };
    bpf_map_update_elem(&kb_cred_prev, &pid, &snap, BPF_ANY);

    if (old_uid == new_uid && old_euid == new_euid && old_cap == new_cap)
        return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e)
        return 0;

    kb_fill_common(e, pid, KB_EVT_PRIVILEGE_CHANGE);
    e->old_uid       = old_uid;
    e->new_uid       = new_uid;
    e->old_euid      = old_euid;
    e->new_euid      = new_euid;
    e->cap_effective = new_cap;
    e->escalation    = (new_uid < old_uid || new_euid == 0) ? 1 : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════
// HOOK 4 — Sensitive File Access
// ═══════════════════════════════════════════════════════════

static __always_inline int is_sensitive_path(const char *fname)
{
    char buf[16] = {};
    bpf_probe_read_user_str(buf, sizeof(buf), fname);

    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' && buf[3]=='c' &&
        buf[4]=='/' && buf[5]=='s' && buf[6]=='h' && buf[7]=='a')
        return 1; // /etc/shadow

    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' && buf[3]=='c' &&
        buf[4]=='/' && buf[5]=='p' && buf[6]=='a' && buf[7]=='s')
        return 1; // /etc/passwd

    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' && buf[3]=='c' &&
        buf[4]=='/' && buf[5]=='s' && buf[6]=='u' && buf[7]=='d')
        return 1; // /etc/sudoers

    if (buf[0]=='/' && buf[1]=='r' && buf[2]=='o' && buf[3]=='o' &&
        buf[4]=='t' && buf[5]=='/')
        return 1; // /root/

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int kb_handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    const char *fname = (const char *)ctx->args[1];
    if (!fname)
        return 0;

    if (!is_sensitive_path(fname))
        return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e)
        return 0;

    kb_fill_common(e, pid, KB_EVT_FILE_ACCESS);
    e->flags     = (__u32)ctx->args[2];
    e->sensitive = 1;
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), fname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════
// HOOK 5 — Network Behavior
// ═══════════════════════════════════════════════════════════

SEC("tracepoint/syscalls/sys_enter_connect")
int kb_handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr)
        return 0;

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    if (family != 2) // AF_INET only
        return 0;

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), addr);

    struct kb_unified_event *e = kb_reserve_event();
    if (!e)
        return 0;

    kb_fill_common(e, pid, KB_EVT_NETWORK_CONNECT);
    e->daddr = sin.sin_addr.s_addr;
    e->dport = __builtin_bswap16(sin.sin_port);
    e->proto = 6; // TCP

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int kb_handle_bind(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr)
        return 0;

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    if (family != 2)
        return 0;

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), addr);

    struct kb_unified_event *e = kb_reserve_event();
    if (!e)
        return 0;

    kb_fill_common(e, pid, KB_EVT_NETWORK_BIND);
    e->saddr = sin.sin_addr.s_addr;
    e->sport = __builtin_bswap16(sin.sin_port);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ═══════════════════════════════════════════════════════════
// HOOK 6 — Memory Mapping
// ═══════════════════════════════════════════════════════════

#define KB_PROT_READ   0x1
#define KB_PROT_WRITE  0x2
#define KB_PROT_EXEC   0x4
#define KB_PROT_RWX    (KB_PROT_READ | KB_PROT_WRITE | KB_PROT_EXEC)
#define KB_MAP_ANON    0x20

SEC("tracepoint/syscalls/sys_enter_mmap")
int kb_handle_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 addr   = (__u64)ctx->args[0];
    __u64 length = (__u64)ctx->args[1];
    __u32 prot   = (__u32)ctx->args[2];
    __u32 flags  = (__u32)ctx->args[3];

    int is_rwx  = (prot & KB_PROT_RWX) == KB_PROT_RWX;
    int is_exec = (prot & KB_PROT_EXEC) != 0;
    int is_anon = (flags & KB_MAP_ANON) != 0;

    if (!is_rwx && !(is_exec && is_anon))
        return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e)
        return 0;

    kb_fill_common(e, pid, KB_EVT_MEMORY_MMAP);
    e->addr        = addr;
    e->length      = length;
    e->prot        = prot;
    e->mmap_flags  = flags;
    e->rwx         = is_rwx ? 1 : 0;
    e->anonymous   = is_anon ? 1 : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int kb_handle_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 addr   = (__u64)ctx->args[0];
    __u64 length = (__u64)ctx->args[1];
    __u32 prot   = (__u32)ctx->args[2];

    if (!(prot & KB_PROT_EXEC))
        return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e)
        return 0;

    kb_fill_common(e, pid, KB_EVT_MEMORY_MPROTECT);
    e->addr   = addr;
    e->length = length;
    e->prot   = prot;
    e->rwx    = ((prot & KB_PROT_RWX) == KB_PROT_RWX) ? 1 : 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}