// SPDX-License-Identifier: GPL-2.0
// KB Core — Memory Mapping Anomaly Monitor (Hook 6)
// Detects RWX mmap patterns, shellcode injection indicators
// Weight: 15% of behavioral risk score

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// mmap/mprotect protection flags
#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4
#define PROT_RWX    (PROT_READ | PROT_WRITE | PROT_EXEC)

// mmap flags
#define MAP_ANONYMOUS 0x20

struct kb_memory_event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u32 uid;
    __u64 addr;       // mapping address
    __u64 length;     // mapping length
    __u32 prot;       // protection flags
    __u32 flags;      // mmap flags
    __u8  event_type; // 0=mmap, 1=mprotect
    __u8  rwx;        // 1 if RWX (dangerous)
    __u8  anonymous;  // 1 if anonymous mapping
    __u64 ts_ns;
};

// Track mmap count per process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, __u64);
} kb_mmap_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kb_memory_events SEC(".maps");

// Hook: mmap syscall
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

    // Update mmap count
    __u64 *count = bpf_map_lookup_elem(&kb_mmap_counts, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&kb_mmap_counts, &pid, &one, BPF_ANY);
    }

    // Only emit if suspicious:
    // - RWX mapping (classic shellcode)
    // - Anonymous executable mapping
    // - Large anonymous mapping followed by exec prot
    int is_rwx  = (prot & PROT_RWX) == PROT_RWX;
    int is_exec = (prot & PROT_EXEC) != 0;
    int is_anon = (flags & MAP_ANONYMOUS) != 0;

    // Emit if RWX or anonymous+executable
    if (!is_rwx && !(is_exec && is_anon))
        return 0;

    struct kb_memory_event *e =
        bpf_ringbuf_reserve(&kb_memory_events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    e->pid        = pid;
    e->ppid       = BPF_CORE_READ(task, real_parent, tgid);
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->addr       = addr;
    e->length     = length;
    e->prot       = prot;
    e->flags      = flags;
    e->event_type = 0; // mmap
    e->rwx        = is_rwx ? 1 : 0;
    e->anonymous  = is_anon ? 1 : 0;
    e->ts_ns      = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: mprotect syscall — changing memory permissions
SEC("tracepoint/syscalls/sys_enter_mprotect")
int kb_handle_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    __u64 addr   = (__u64)ctx->args[0];
    __u64 length = (__u64)ctx->args[1];
    __u32 prot   = (__u32)ctx->args[2];

    // Only emit if adding execute permission
    // W^X violation: write then execute is classic exploit pattern
    if (!(prot & PROT_EXEC))
        return 0;

    struct kb_memory_event *e =
        bpf_ringbuf_reserve(&kb_memory_events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    e->pid        = pid;
    e->ppid       = BPF_CORE_READ(task, real_parent, tgid);
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->addr       = addr;
    e->length     = length;
    e->prot       = prot;
    e->event_type = 1; // mprotect
    e->rwx        = ((prot & PROT_RWX) == PROT_RWX) ? 1 : 0;
    e->ts_ns      = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}