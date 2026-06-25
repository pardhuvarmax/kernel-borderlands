// SPDX-License-Identifier: GPL-2.0
// KB Core — Process Lifecycle Hook
// Captures fork/exec/exit for lineage tracking

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Event types
#define KB_EVENT_EXEC  0
#define KB_EVENT_EXIT  1
#define KB_EVENT_FORK  2

// KB process event structure
struct kb_process_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u8  comm[16];
    __u8  filename[64];
    __u8  event_type;
    __u64 ts_ns;
};

// Ring buffer for zero-copy event emission to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); // 512KB
} kb_events SEC(".maps");

// Per-process state map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // pid
    __type(value, __u32); // ppid
} kb_lineage SEC(".maps");

// Hook: process exec
SEC("tp/sched/sched_process_exec")
int kb_handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct kb_process_event *e;
    struct task_struct *task;
    __u32 pid, ppid;

    e = bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
    if (!e)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();
    pid  = bpf_get_current_pid_tgid() >> 32;
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->pid        = pid;
    e->ppid       = ppid;
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid        = bpf_get_current_uid_gid() >> 32;
    e->event_type = KB_EVENT_EXEC;
    e->ts_ns      = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Track lineage
    bpf_map_update_elem(&kb_lineage, &pid, &ppid, BPF_ANY);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: process exit
SEC("tp/sched/sched_process_exit")
int kb_handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct kb_process_event *e;
    __u32 pid;

    e = bpf_ringbuf_reserve(&kb_events, sizeof(*e), 0);
    if (!e)
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;

    e->pid        = pid;
    e->event_type = KB_EVENT_EXIT;
    e->ts_ns      = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Remove from lineage map
    bpf_map_delete_elem(&kb_lineage, &pid);

    bpf_ringbuf_submit(e, 0);
    return 0;
}