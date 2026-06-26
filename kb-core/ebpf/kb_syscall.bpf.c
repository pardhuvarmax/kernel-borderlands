// SPDX-License-Identifier: GPL-2.0
// KB Core — Syscall Entropy Tracker (Hook 2)
// Tracks per-process syscall distributions for KL divergence scoring
// Weight: 25% of behavioral risk score

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Maximum number of unique syscalls we track per process
#define KB_MAX_SYSCALLS     512
#define KB_MAX_PROCESSES    10240

// Syscall event emitted to userspace
struct kb_syscall_event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u32 syscall_nr;
    __u64 ts_ns;
    __u32 uid;
};

// Per-process syscall count map
// Key: (pid << 32 | syscall_nr)
// Value: count
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KB_MAX_PROCESSES * 64);
    __type(key,   __u64);
    __type(value, __u64);
} kb_syscall_counts SEC(".maps");

// Per-process total syscall count (for normalization)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KB_MAX_PROCESSES);
    __type(key,   __u32); // pid
    __type(value, __u64); // total count
} kb_syscall_totals SEC(".maps");

// Ring buffer for emitting events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} kb_syscall_events SEC(".maps");

// Hook: every syscall entry
SEC("tracepoint/raw_syscalls/sys_enter")
int kb_handle_syscall(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    long  syscall_nr = ctx->id;

    // Skip kernel threads (pid 0) and negative syscall numbers
    if (pid == 0 || syscall_nr < 0)
        return 0;

    // Skip if thread (only track per-process, not per-thread)
    if (pid != tid)
        return 0;

    // Update per-process syscall count
    __u64 key = ((__u64)pid << 32) | (__u32)syscall_nr;
    __u64 *count = bpf_map_lookup_elem(&kb_syscall_counts, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&kb_syscall_counts, &key, &one, BPF_ANY);
    }

    // Update total syscall count for this process
    __u64 *total = bpf_map_lookup_elem(&kb_syscall_totals, &pid);
    if (total) {
        __sync_fetch_and_add(total, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&kb_syscall_totals, &pid, &one, BPF_ANY);
    }

    // Emit event every 100 syscalls (sampling to reduce overhead)
    __u64 *t = bpf_map_lookup_elem(&kb_syscall_totals, &pid);
    if (!t || (*t % 100 != 0))
        return 0;

    // Emit sampled event to userspace for scoring
    struct kb_syscall_event *e;
    e = bpf_ringbuf_reserve(&kb_syscall_events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    e->pid        = pid;
    e->ppid       = BPF_CORE_READ(task, real_parent, tgid);
    e->syscall_nr = (__u32)syscall_nr;
    e->ts_ns      = bpf_ktime_get_ns();
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}