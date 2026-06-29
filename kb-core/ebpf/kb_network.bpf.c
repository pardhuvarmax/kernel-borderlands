// SPDX-License-Identifier: GPL-2.0
// KB Core — Network Behavior Monitor (Hook 5)
// Tracks unexpected connection patterns
// Weight: 10% of behavioral risk score

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct kb_network_event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u32 uid;
    __u32 saddr;     // source IP (IPv4)
    __u32 daddr;     // dest IP (IPv4)
    __u16 sport;     // source port
    __u16 dport;     // dest port
    __u8  proto;     // 6=TCP, 17=UDP
    __u8  direction; // 0=outbound, 1=inbound
    __u64 ts_ns;
};

// Track connection count per process (burst detection)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32); // pid
    __type(value, __u64); // connection count
} kb_conn_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kb_network_events SEC(".maps");

// Hook: connect() syscall — outbound connections
SEC("tracepoint/syscalls/sys_enter_connect")
int kb_handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0)
        return 0;

    // Update connection count for burst detection
    __u64 *count = bpf_map_lookup_elem(&kb_conn_counts, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&kb_conn_counts, &pid, &one, BPF_ANY);
    }

    // Read sockaddr from args
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr)
        return 0;

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    // Only handle IPv4 for now
    if (family != 2) // AF_INET = 2
        return 0;

    struct kb_network_event *e =
        bpf_ringbuf_reserve(&kb_network_events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    // Read IPv4 sockaddr
    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), addr);

    e->pid       = pid;
    e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
    e->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->daddr     = sin.sin_addr.s_addr;
    e->dport     = __builtin_bswap16(sin.sin_port);
    e->proto     = 6; // TCP assumed for connect()
    e->direction = 0; // outbound
    e->ts_ns     = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: bind() syscall — listening ports
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

    struct kb_network_event *e =
        bpf_ringbuf_reserve(&kb_network_events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), addr);

    e->pid       = pid;
    e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
    e->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->saddr     = sin.sin_addr.s_addr;
    e->sport     = __builtin_bswap16(sin.sin_port);
    e->direction = 1; // inbound (bind = server listening)
    e->ts_ns     = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}