#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "../.output/kb_network.skel.h"

struct kb_network_event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];
    __u32 uid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  direction;
    __u64 ts_ns;
};

static volatile int running = 1;
void handle_sigint(int sig) { running = 0; }

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct kb_network_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &e->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &e->daddr, dst, sizeof(dst));

    printf("[%s] PID=%-6u COMM=%-16s "
           "%s:%u → %s:%u proto=%s\n",
           e->direction ? "BIND   " : "CONNECT",
           e->pid, e->comm,
           src, e->sport,
           dst, e->dport,
           e->proto == 6 ? "TCP" : "UDP");

    return 0;
}

int main(void)
{
    struct kb_network_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, handle_sigint);

    printf("╔══════════════════════════════════════════╗\n");
    printf("║  KB Core — Network Monitor               ║\n");
    printf("║  Hook 5 / Weight: 10%%                   ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    skel = kb_network_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = kb_network_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach\n");
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.kb_network_events),
        handle_event, NULL, NULL);
    if (!rb) goto cleanup;

    printf("%-9s %-6s %-16s %s\n",
           "TYPE", "PID", "COMM", "CONNECTION");
    printf("──────────────────────────────────────────────\n");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }

cleanup:
    ring_buffer__free(rb);
    kb_network_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}