// SPDX-License-Identifier: GPL-2.0
// KB Core — Sensitive File Access Monitor (Hook 4)
// Uses LSM hooks to track access to sensitive paths
// Weight: 10% of behavioral risk score

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct kb_file_event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u8  filename[128];
    __u32 uid;
    __u32 flags;         // open flags (read/write/exec)
    __u8  sensitive;     // 1 if path is sensitive
    __u64 ts_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kb_file_events SEC(".maps");

// Check if filename contains a sensitive path prefix
static __always_inline int is_sensitive_path(const char *fname)
{
    // We check the first few chars of common sensitive paths
    // /etc/shadow, /etc/passwd, /etc/sudoers
    // /root/, /proc/*/mem, /.ssh/
    char buf[16] = {};
    bpf_probe_read_kernel_str(buf, sizeof(buf), fname);

    // /etc/shadow
    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' &&
        buf[3]=='c' && buf[4]=='/' && buf[5]=='s' &&
        buf[6]=='h' && buf[7]=='a')
        return 1;

    // /etc/passwd
    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' &&
        buf[3]=='c' && buf[4]=='/' && buf[5]=='p' &&
        buf[6]=='a' && buf[7]=='s')
        return 1;

    // /etc/sudoers
    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' &&
        buf[3]=='c' && buf[4]=='/' && buf[5]=='s' &&
        buf[6]=='u' && buf[7]=='d')
        return 1;

    // /root/
    if (buf[0]=='/' && buf[1]=='r' && buf[2]=='o' &&
        buf[3]=='o' && buf[4]=='t' && buf[5]=='/')
        return 1;

    // /.ssh/
    if (buf[5]=='.' && buf[6]=='s' && buf[7]=='s' && buf[8]=='h')
        return 1;

    return 0;
}

// Hook: file open via tracepoint (broader coverage than LSM)
SEC("tracepoint/syscalls/sys_enter_openat")
int kb_handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    // Get filename from syscall args
    const char *fname = (const char *)ctx->args[1];
    if (!fname)
        return 0;

    // Check if path is sensitive
    int sensitive = is_sensitive_path(fname);

    // Only emit if sensitive (to reduce noise)
    // For full file tracking, remove this check
    if (!sensitive)
        return 0;

    struct kb_file_event *e =
        bpf_ringbuf_reserve(&kb_file_events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    e->pid       = pid;
    e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
    e->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->flags     = (__u32)ctx->args[2];
    e->sensitive = 1;
    e->ts_ns     = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), fname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}