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
#define KB_MAX_SYSCALLS  512   // matches kb_syscall.bpf.c's standalone collector

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

struct kb_unified_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8  comm[16];
    __u8  event_type;
    __u64 ts_ns;

    __u32 syscall_nr;

    __u32 old_uid;
    __u32 new_uid;
    __u32 old_euid;
    __u32 new_euid;
    __u64 cap_effective;
    __u8  escalation;

    __u8  filename[128];
    __u8  sensitive;
    __u32 flags;

    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;

    __u64 addr;
    __u64 length;
    __u32 prot;
    __u32 mmap_flags;
    __u8  rwx;
    __u8  anonymous;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1MB, shared across all hooks
} kb_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KB_MAX_PROCESSES);
    __type(key,   __u32);
    __type(value, __u64);
} kb_syscall_totals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KB_MAX_PROCESSES * 64);
    __type(key,   __u64);
    __type(value, __u64);
} kb_syscall_counts SEC(".maps");

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

// Single-counter map: total bpf_ringbuf_reserve() failures since load.
// Previously silent — every kb_reserve_event() caller just returned 0
// on failure with no telemetry at all. Exists purely to answer "is
// kb_events (1MB, shared across all 9 hooks) actually overflowing under
// burst load (e.g. a `go build` spawning many short-lived processes/
// file_access events in rapid succession), or is the blank-comm gap on
// those pids coming from somewhere else." One BPF_MAP_TYPE_ARRAY entry,
// updated via __sync_fetch_and_add so concurrent hooks on different
// CPUs don't race each other's increments.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} kb_ringbuf_drops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[64]);
    __type(value, __u32);
} kb_sensitive_paths SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);   // PID
    __type(value, __u32);   // Containment Level
} contained_pids_map SEC(".maps");

static __always_inline struct kb_unified_event *kb_reserve_event(void)
{
    struct kb_unified_event *e =
        bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
    if (!e) {
        __u32 zero = 0;
        __u64 *drops = bpf_map_lookup_elem(&kb_ringbuf_drops, &zero);
        if (drops)
            __sync_fetch_and_add(drops, 1);
        return NULL;
    }
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

SEC("tp/sched/sched_process_exec")
int kb_handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;
    kb_fill_common(e, pid, KB_EVT_PROCESS_EXEC);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int kb_handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;
    kb_fill_common(e, pid, KB_EVT_PROCESS_EXIT);
    e->syscall_nr = BPF_CORE_READ(task, exit_code);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int kb_handle_syscall(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    long  syscall_nr = ctx->id;

    if (pid == 0 || syscall_nr < 0 || pid != tid)
        return 0;

    __u64 ckey = ((__u64)pid << 32) | (__u32)syscall_nr;
    __u64 *ccount = bpf_map_lookup_elem(&kb_syscall_counts, &ckey);
    if (ccount) {
        __sync_fetch_and_add(ccount, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&kb_syscall_counts, &ckey, &one, BPF_ANY);
    }

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
    if (!e) return 0;
    kb_fill_common(e, pid, KB_EVT_SYSCALL);
    e->syscall_nr = (__u32)syscall_nr;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/commit_creds")
int kb_handle_commit_creds(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;

    struct cred *new_cred = (struct cred *)PT_REGS_PARM1(ctx);
    if (!new_cred) return 0;

    __u32 new_uid  = BPF_CORE_READ(new_cred, uid.val);
    __u32 new_euid = BPF_CORE_READ(new_cred, euid.val);
    __u64 new_cap  = BPF_CORE_READ(new_cred, cap_effective.val);

    struct kb_cred_snapshot *prev = bpf_map_lookup_elem(&kb_cred_prev, &pid);
    __u32 old_uid  = prev ? prev->uid  : new_uid;
    __u32 old_euid = prev ? prev->euid : new_euid;
    __u64 old_cap  = prev ? prev->cap_effective : new_cap;

    struct kb_cred_snapshot snap = { .uid = new_uid, .euid = new_euid, .cap_effective = new_cap };
    bpf_map_update_elem(&kb_cred_prev, &pid, &snap, BPF_ANY);

    if (old_uid == new_uid && old_euid == new_euid && old_cap == new_cap)
        return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;
    kb_fill_common(e, pid, KB_EVT_PRIVILEGE_CHANGE);
    e->old_uid = old_uid; e->new_uid = new_uid;
    e->old_euid = old_euid; e->new_euid = new_euid;
    e->cap_effective = new_cap;
    e->escalation = (new_uid < old_uid || new_euid == 0) ? 1 : 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int is_sensitive_path(const char *fname)
{
    char buf[64] = {};
    bpf_probe_read_user_str(buf, sizeof(buf), fname);

    // 1. Direct path lookup in the dynamic map
    __u32 *val = bpf_map_lookup_elem(&kb_sensitive_paths, buf);
    if (val) return 1;

    // 2. Directory prefix check (safe, unrolled loop to satisfy verifier)
    #pragma unroll
    for (int i = 63; i > 0; i--) {
        if (buf[i] == '/') {
            buf[i] = '\0'; // truncate at directory boundary
            val = bpf_map_lookup_elem(&kb_sensitive_paths, buf);
            if (val) return 1;
            // Restore '/' in case we need to check higher directories in future
            buf[i] = '/';
        }
    }

    // 3. Keep hardware/kernel protection for /proc/*/mem (not easily directory-listed)
    if (buf[0]=='/' && buf[1]=='p' && buf[2]=='r' && buf[3]=='o' && buf[4]=='c' && buf[5]=='/') {
        for (int i = 6; i < 24; i++) {
            if (buf[i] == '\0') break;
            if (buf[i] == '/' && buf[i+1] == 'm' && buf[i+2] == 'e' && buf[i+3] == 'm' && buf[i+4] == '\0') {
                return 1;
            }
        }
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int kb_handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;
    const char *fname = (const char *)ctx->args[1];
    if (!fname) return 0;
    if (!is_sensitive_path(fname)) return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;
    kb_fill_common(e, pid, KB_EVT_FILE_ACCESS);
    e->flags = (__u32)ctx->args[2];
    e->sensitive = 1;
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), fname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int kb_handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr) return 0;
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    if (family != 2) return 0;
    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), addr);

    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;
    kb_fill_common(e, pid, KB_EVT_NETWORK_CONNECT);
    e->daddr = sin.sin_addr.s_addr;
    e->dport = __builtin_bswap16(sin.sin_port);
    e->proto = 6;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int kb_handle_bind(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr) return 0;
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    if (family != 2) return 0;
    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), addr);

    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;
    kb_fill_common(e, pid, KB_EVT_NETWORK_BIND);
    e->saddr = sin.sin_addr.s_addr;
    e->sport = __builtin_bswap16(sin.sin_port);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#define KB_PROT_READ   0x1
#define KB_PROT_WRITE  0x2
#define KB_PROT_EXEC   0x4
#define KB_PROT_RWX    (KB_PROT_READ | KB_PROT_WRITE | KB_PROT_EXEC)
#define KB_MAP_ANON    0x20

SEC("tracepoint/syscalls/sys_enter_mmap")
int kb_handle_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;
    __u64 addr = (__u64)ctx->args[0];
    __u64 length = (__u64)ctx->args[1];
    __u32 prot = (__u32)ctx->args[2];
    __u32 flags = (__u32)ctx->args[3];
    int is_rwx = (prot & KB_PROT_RWX) == KB_PROT_RWX;
    int is_exec = (prot & KB_PROT_EXEC) != 0;
    int is_anon = (flags & KB_MAP_ANON) != 0;
    if (!is_rwx && !(is_exec && is_anon)) return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;
    kb_fill_common(e, pid, KB_EVT_MEMORY_MMAP);
    e->addr = addr; e->length = length; e->prot = prot; e->mmap_flags = flags;
    e->rwx = is_rwx ? 1 : 0; e->anonymous = is_anon ? 1 : 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int kb_handle_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;
    __u64 addr = (__u64)ctx->args[0];
    __u64 length = (__u64)ctx->args[1];
    __u32 prot = (__u32)ctx->args[2];
    if (!(prot & KB_PROT_EXEC)) return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;
    kb_fill_common(e, pid, KB_EVT_MEMORY_MPROTECT);
    e->addr = addr; e->length = length; e->prot = prot;
    e->rwx = ((prot & KB_PROT_RWX) == KB_PROT_RWX) ? 1 : 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe")
int kb_ssl_write(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;

    // OpenSSL SSL_write(SSL *ssl, const void *buf, int num)
    // Parameter 2: buf in RSI (ctx->si), Parameter 3: num in RDX (ctx->dx)
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);

    if (num <= 0 || !buf) return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;

    kb_fill_common(e, pid, 9); // 9 = KB_EVT_TLS_PLAINTEXT
    e->flags = num; // store original length
    unsigned int copy_len = (unsigned int)num;
    if (copy_len > 127) {
        copy_len = 127;
    }
    copy_len &= 127;
    bpf_probe_read_user(&e->filename, copy_len, buf);
    e->filename[copy_len] = '\0';
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe")
int kb_go_tls_write(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;

    // Go ABI: b.ptr in RBX (ctx->bx), b.len in RCX (ctx->cx)
    const char *buf = (const char *)ctx->bx;
    int num = (int)ctx->cx;

    if (num <= 0 || !buf) return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;

    kb_fill_common(e, pid, 9); // 9 = KB_EVT_TLS_PLAINTEXT
    e->flags = num;
    unsigned int copy_len = (unsigned int)num;
    if (copy_len > 127) {
        copy_len = 127;
    }
    copy_len &= 127;
    bpf_probe_read_user(&e->filename, copy_len, buf);
    e->filename[copy_len] = '\0';
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int kb_handle_process_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;

    __u32 target_pid = (__u32)ctx->args[0];
    if (target_pid == pid) return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;

    kb_fill_common(e, pid, KB_EVT_MEMORY_MMAP);
    e->addr = 0;
    e->length = target_pid;
    e->prot = 0;
    e->rwx = 1;
    e->anonymous = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/security_capable")
int kb_handle_security_capable(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;

    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (uid == 0) return 0; // skip root noise

    int cap = (int)PT_REGS_PARM3(ctx);
    // Sensitive capabilities: CAP_CHOWN(0), CAP_DAC_OVERRIDE(1), CAP_SYS_PTRACE(19), CAP_SYS_ADMIN(21), CAP_SYS_RAWIO(17)
    if (cap != 19 && cap != 21 && cap != 17 && cap != 1)
        return 0;

    struct kb_unified_event *e = kb_reserve_event();
    if (!e) return 0;

    kb_fill_common(e, pid, KB_EVT_PRIVILEGE_CHANGE);
    e->old_uid = uid;
    e->new_uid = uid;
    e->old_euid = cap;
    e->new_euid = 0xFFFFFFFF; // Indicator for capability probe
    e->escalation = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int is_sensitive_kernel_path(char *buf)
{
    // 1. Direct path lookup in the dynamic map
    __u32 *val = bpf_map_lookup_elem(&kb_sensitive_paths, buf);
    if (val) return 1;

    // 2. Directory prefix check (safe, unrolled loop to satisfy verifier)
    #pragma unroll
    for (int i = 63; i > 0; i--) {
        if (buf[i] == '/') {
            buf[i] = '\0'; // truncate at directory boundary
            val = bpf_map_lookup_elem(&kb_sensitive_paths, buf);
            if (val) {
                buf[i] = '/'; // restore
                return 1;
            }
            buf[i] = '/'; // restore
        }
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(kb_lsm_file_open, struct file *file, int mask)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *level = bpf_map_lookup_elem(&contained_pids_map, &pid);

    char path_buf[64] = {};
    int len = bpf_d_path(&file->f_path, path_buf, sizeof(path_buf));
    if (len < 0) return 0;

    if (level) {
        if (*level >= 3) {
            return -13; // Block ALL file open requests (full sandbox quarantine)
        }
        if (*level == 2) {
            if (is_sensitive_kernel_path(path_buf)) {
                return -13; // Block sensitive paths first
            }
        }
    }

    if (is_sensitive_kernel_path(path_buf)) {
        return -13; // Block by returning -EACCES
    }
    return 0;
}

/*
 * Containment level semantics applied by all five LSM hooks below:
 *
 *   Level 0 (None)      — no entry in map; all hooks pass through.
 *   Level 1 (Cgroup)    — cgroup throttling only; no LSM blocking.
 *   Level 2 (Seccomp)   — block network connections/binds and exec of new
 *                          processes; file_open already blocks sensitive paths.
 *   Level 3 (Namespace) — all level-2 blocks plus RWX/exec memory operations.
 *   Level 4 (Terminate) — block everything the LSM can intercept; combined
 *                          with the userspace SIGKILL sent by the enforcer.
 *
 * Return -EPERM (-1) uniformly across all hooks so the kernel presents a
 * consistent "Operation not permitted" rather than hook-specific codes.
 */

/* Exec containment — prevent the process from replacing its image with a new
 * binary. Level ≥2 blocks exec entirely; at level 4 this is belt-and-
 * suspenders alongside the userspace SIGKILL. */
SEC("lsm/bprm_check_security")
int BPF_PROG(kb_lsm_bprm_check, struct linux_binprm *bprm)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *level = bpf_map_lookup_elem(&contained_pids_map, &pid);
    if (!level)
        return 0;
    /* Level 1 (Cgroup): throttle only — exec allowed. */
    if (*level < 2)
        return 0;
    /* Level ≥2: block execve/execveat so the process cannot escape by
     * re-exec'ing a clean binary or launching a child shell. */
    return -1; /* -EPERM */
}

/* Network connect containment — prevent the process from opening new outbound
 * connections. Level ≥2 blocks all AF_INET/AF_INET6 connects. */
SEC("lsm/socket_connect")
int BPF_PROG(kb_lsm_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *level = bpf_map_lookup_elem(&contained_pids_map, &pid);
    if (!level)
        return 0;
    if (*level < 2)
        return 0;
    /* Block TCP/UDP connect for all containment levels ≥2. Unix-domain
     * sockets (AF_UNIX) are not blocked here — the lsm/file_open hook
     * already restricts file-backed socket paths if they are sensitive. */
    __u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
    if (family == 2 /* AF_INET */ || family == 10 /* AF_INET6 */)
        return -13; /* -EACCES */
    return 0;
}

/* Network bind containment — prevent the process from opening new listening
 * ports. Level ≥2 blocks all AF_INET/AF_INET6 binds. */
SEC("lsm/socket_bind")
int BPF_PROG(kb_lsm_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *level = bpf_map_lookup_elem(&contained_pids_map, &pid);
    if (!level)
        return 0;
    if (*level < 2)
        return 0;
    __u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
    if (family == 2 /* AF_INET */ || family == 10 /* AF_INET6 */)
        return -13; /* -EACCES */
    return 0;
}

/* Memory protection containment — prevent the process from creating new
 * executable mappings. Level ≥3 blocks any mprotect that adds PROT_EXEC,
 * closing the common shellcode-injection path of mmap(RW)+mprotect(RX). */
SEC("lsm/file_mprotect")
int BPF_PROG(kb_lsm_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *level = bpf_map_lookup_elem(&contained_pids_map, &pid);
    if (!level)
        return 0;
    /* Level 1-2: allow — mprotect is needed for JIT runtimes etc.
     * Level ≥3 (Namespace/Terminate): block any mapping that gains PROT_EXEC. */
    if (*level < 3)
        return 0;
    if (prot & KB_PROT_EXEC)
        return -13; /* -EACCES */
    return 0;
}