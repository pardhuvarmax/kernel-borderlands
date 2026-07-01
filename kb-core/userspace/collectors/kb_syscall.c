#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <bpf/libbpf.h>
#include "../.output/kb_syscall.skel.h"

// Syscall names for display (x86_64)
static const char *syscall_names[] = {
    "read", "write", "open", "close", "stat", "fstat",
    "lstat", "poll", "lseek", "mmap", "mprotect", "munmap",
    "brk", "rt_sigaction", "rt_sigprocmask", "ioctl",
    "pread64", "pwrite64", "readv", "writev", "access",
    "pipe", "select", "sched_yield", "mremap", "msync",
    "mincore", "madvise", "shmget", "shmat", "shmctl",
    "dup", "dup2", "pause", "nanosleep", "getitimer",
    "alarm", "setitimer", "getpid", "sendfile", "socket",
    "connect", "accept", "sendto", "recvfrom", "sendmsg",
    "recvmsg", "shutdown", "bind", "listen", "getsockname",
    "getpeername", "socketpair", "setsockopt", "getsockopt",
    "clone", "fork", "vfork", "execve", "exit", "wait4",
    "kill", "uname", "semget", "semop", "semctl", "shmdt",
    "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock",
    "fsync", "fdatasync", "truncate", "ftruncate",
};

#define SYSCALL_NAMES_COUNT \
    (sizeof(syscall_names) / sizeof(syscall_names[0]))

struct kb_syscall_event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u32 syscall_nr;
    __u64 ts_ns;
    __u32 uid;
};

static volatile int running = 1;
void handle_sigint(int sig) { running = 0; }

static const char *get_syscall_name(__u32 nr) {
    if (nr < SYSCALL_NAMES_COUNT)
        return syscall_names[nr];
    return "unknown";
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct kb_syscall_event *e = data;

    printf("[SYSCALL] PID=%-6u PPID=%-6u UID=%-5u "
           "COMM=%-16s NR=%-4u (%s)\n",
           e->pid, e->ppid, e->uid,
           e->comm, e->syscall_nr,
           get_syscall_name(e->syscall_nr));

    return 0;
}

int main(void)
{
    struct kb_syscall_bpf *skel;
    struct ring_buffer    *rb = NULL;
    int err;

    signal(SIGINT, handle_sigint);

    printf("╔══════════════════════════════════════════╗\n");
    printf("║  KB Core — Syscall Entropy Tracker       ║\n");
    printf("║  Hook 2 / Weight: 25%%                   ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    skel = kb_syscall_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = kb_syscall_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.kb_syscall_events),
        handle_event, NULL, NULL
    );
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("%-8s %-6s %-6s %-5s %-16s %-4s %s\n",
           "TYPE", "PID", "PPID", "UID", "COMM", "NR", "SYSCALL");
    printf("──────────────────────────────────────────────\n");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

cleanup:
    ring_buffer__free(rb);
    kb_syscall_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}