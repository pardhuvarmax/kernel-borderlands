// SPDX-License-Identifier: GPL-2.0
// KB Core — Privilege Change Monitor (Hook 3)
// Tracks privilege escalation via commit_creds kprobe
// Weight: 20% of behavioral risk score

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define KB_MAX_PROCESSES 10240

struct kb_privilege_event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u32 old_uid;
    __u32 new_uid;
    __u32 old_gid;
    __u32 new_gid;
    __u32 old_euid;
    __u32 new_euid;
    __u64 cap_effective; // capability set
    __u64 ts_ns;
    __u8  escalation;    // 1 if privilege increased
};

// Store previous uid per process for delta computation
struct kb_cred_snapshot {
    __u32 uid;
    __u32 gid;
    __u32 euid;
    __u64 cap_effective;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, KB_MAX_PROCESSES);
    __type(key,   __u32); // pid
    __type(value, struct kb_cred_snapshot);
} kb_cred_prev SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kb_privilege_events SEC(".maps");

// Hook on commit_creds — called every time credentials change
SEC("kprobe/commit_creds")
int kb_handle_commit_creds(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    // Get new credentials being committed
    struct cred *new_cred = (struct cred *)PT_REGS_PARM1(ctx);
    if (!new_cred)
        return 0;

    __u32 new_uid  = BPF_CORE_READ(new_cred, uid.val);
    __u32 new_gid  = BPF_CORE_READ(new_cred, gid.val);
    __u32 new_euid = BPF_CORE_READ(new_cred, euid.val);
    __u64 new_cap = BPF_CORE_READ(new_cred, cap_effective.val);
    
    // Look up previous credentials
    struct kb_cred_snapshot *prev =
        bpf_map_lookup_elem(&kb_cred_prev, &pid);

    __u32 old_uid  = prev ? prev->uid  : new_uid;
    __u32 old_gid  = prev ? prev->gid  : new_gid;
    __u32 old_euid = prev ? prev->euid : new_euid;
    __u64 old_cap  = prev ? prev->cap_effective : new_cap;

    // Only emit if credentials actually changed
    if (old_uid == new_uid && old_gid == new_gid &&
        old_euid == new_euid && old_cap == new_cap) {
        // Update snapshot and return
        struct kb_cred_snapshot snap = {
            .uid = new_uid, .gid = new_gid,
            .euid = new_euid, .cap_effective = new_cap
        };
        bpf_map_update_elem(&kb_cred_prev, &pid, &snap, BPF_ANY);
        return 0;
    }

    // Emit privilege change event
    struct kb_privilege_event *e =
        bpf_ringbuf_reserve(&kb_privilege_events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    e->pid          = pid;
    e->ppid         = BPF_CORE_READ(task, real_parent, tgid);
    e->old_uid      = old_uid;
    e->new_uid      = new_uid;
    e->old_gid      = old_gid;
    e->new_gid      = new_gid;
    e->old_euid     = old_euid;
    e->new_euid     = new_euid;
    e->cap_effective = new_cap;
    e->ts_ns        = bpf_ktime_get_ns();
    e->escalation   = (new_uid < old_uid || new_euid == 0) ? 1 : 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Update snapshot
    struct kb_cred_snapshot snap = {
        .uid = new_uid, .gid = new_gid,
        .euid = new_euid, .cap_effective = new_cap
    };
    bpf_map_update_elem(&kb_cred_prev, &pid, &snap, BPF_ANY);

    bpf_ringbuf_submit(e, 0);
    return 0;
}