// SPDX-License-Identifier: GPL-2.0
// KB Core — IPC bridge implementation.
//
// Framing on the wire (both message kinds): 4-byte little-endian
// length prefix, then that many bytes of payload. Length covers the
// payload only, not the 4-byte prefix itself. This framing survives
// the later swap to real protobuf payloads unchanged — only what
// goes inside the length-prefixed frame changes.

#include "kb_bridge.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

#define KB_WIRE_MAGIC    0x4B42  // "KB"
#define KB_WIRE_VERSION  3  // v3: added start_time_ns to ZoneTransition (PID-reuse guard)

#define KB_WIRE_MSG_PROCESS_STATE    1
#define KB_WIRE_MSG_ZONE_TRANSITION  2

#pragma pack(push, 1)
struct kb_wire_header {
    uint16_t magic;
    uint8_t  version;
    uint8_t  msg_type;
};

struct kb_wire_process_state {
    struct kb_wire_header hdr;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char     comm[16];
    uint64_t start_time_ns;
    uint64_t last_updated_ns;
    double   dim_score[KB_DIM_COUNT];      // dim_score[KB_DIM_SYSCALL] is windowed
    double   composite_score;
    double   ema_score;
    double   syscall_entropy_lifetime;     // advisory, not part of composite/ema
    uint32_t zone;
    uint32_t event_count;
};

struct kb_wire_zone_transition {
    struct kb_wire_header hdr;
    uint32_t pid;
    uint64_t start_time_ns;  // pid-reuse guard — enforcement should
                              // verify this still matches the pid's
                              // known start time before acting, since
                              // pids get reused and a stale/reused pid
                              // must not get contained by mistake.
    uint32_t from_zone;
    uint32_t to_zone;
    double   score;
    uint64_t ts_ns;
};
#pragma pack(pop)

// ---- socket path ----

const char *kb_bridge_socket_path(void)
{
    const char *sock = getenv("KB_SOCKET_PATH");
    if (sock && sock[0] != '\0')
        return sock;
    return KB_BRIDGE_DEFAULT_SOCK;
}

// ---- connection lifecycle ----

static int connect_once(const char *sock_path)
{
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

int kb_bridge_try_connect(const char *sock_path)
{
    return connect_once(sock_path);
}

int kb_bridge_connect(const char *sock_path, int max_attempts)
{
    int delay_ms = KB_BRIDGE_RETRY_MIN_MS;
    int attempt = 0;

    for (;;) {
        int fd = connect_once(sock_path);
        if (fd >= 0)
            return fd;

        attempt++;
        if (max_attempts > 0 && attempt >= max_attempts)
            return -1;

        struct timespec ts = {
            .tv_sec  = delay_ms / 1000,
            .tv_nsec = (delay_ms % 1000) * 1000000L,
        };
        nanosleep(&ts, NULL);

        delay_ms *= 2;
        if (delay_ms > KB_BRIDGE_RETRY_MAX_MS)
            delay_ms = KB_BRIDGE_RETRY_MAX_MS;
    }
}

void kb_bridge_close(int fd)
{
    if (fd >= 0)
        close(fd);
}

// ---- framed send helper ----

// Writes a 4-byte LE length prefix (payload length, not counting the
// prefix) followed by the payload. Loops on short writes; treats any
// write() error (including EPIPE/ECONNRESET from a dead peer) as a
// hard failure the caller must react to by reconnecting.
static int send_framed(int fd, const void *payload, size_t len)
{
    uint8_t len_prefix[4] = {
        (uint8_t)(len & 0xFF),
        (uint8_t)((len >> 8) & 0xFF),
        (uint8_t)((len >> 16) & 0xFF),
        (uint8_t)((len >> 24) & 0xFF),
    };

    struct iovec_like { const uint8_t *base; size_t len; } parts[2] = {
        { len_prefix, sizeof(len_prefix) },
        { (const uint8_t *)payload, len },
    };

    for (int p = 0; p < 2; p++) {
        size_t sent = 0;
        while (sent < parts[p].len) {
            ssize_t n = write(fd, parts[p].base + sent, parts[p].len - sent);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                return -1; // EPIPE/ECONNRESET/etc — connection is dead
            }
            sent += (size_t)n;
        }
    }
    return 0;
}

// ---- sends ----

int kb_bridge_send_state(int fd, const kb_process_state_t *s)
{
    if (!s) { errno = EINVAL; return -1; }

    struct kb_wire_process_state w = {0};
    w.hdr.magic    = KB_WIRE_MAGIC;
    w.hdr.version  = KB_WIRE_VERSION;
    w.hdr.msg_type = KB_WIRE_MSG_PROCESS_STATE;

    w.pid              = s->pid;
    w.ppid             = s->ppid;
    w.uid              = s->uid;
    memcpy(w.comm, s->comm, sizeof(w.comm));
    w.start_time_ns    = s->start_time_ns;
    w.last_updated_ns  = s->last_updated_ns;
    memcpy(w.dim_score, s->dim_score, sizeof(w.dim_score));
    w.composite_score          = s->composite_score;
    w.ema_score                = s->ema_score;
    w.syscall_entropy_lifetime = s->syscall_entropy_lifetime;
    w.zone                     = (uint32_t)s->zone;
    w.event_count              = s->event_count;

    return send_framed(fd, &w, sizeof(w));
}

int kb_bridge_send_zone_transition(int fd, uint32_t pid, uint64_t start_time_ns,
                                    kb_zone_t from, kb_zone_t to,
                                    double score, uint64_t ts_ns)
{
    struct kb_wire_zone_transition w = {0};
    w.hdr.magic    = KB_WIRE_MAGIC;
    w.hdr.version  = KB_WIRE_VERSION;
    w.hdr.msg_type = KB_WIRE_MSG_ZONE_TRANSITION;

    w.pid            = pid;
    w.start_time_ns  = start_time_ns;
    w.from_zone      = (uint32_t)from;
    w.to_zone        = (uint32_t)to;
    w.score          = score;
    w.ts_ns          = ts_ns;

    return send_framed(fd, &w, sizeof(w));
}