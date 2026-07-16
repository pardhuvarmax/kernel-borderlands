// SPDX-License-Identifier: GPL-2.0
// KB Core — IPC bridge from kbd_sensor (C) to the Go control-plane
// daemon (Tejaswini's kbd), over a Unix domain socket.
//
// STOPGAP WIRE FORMAT: kb_ipc.proto doesn't exist yet. Rather than
// block on it, this sends a hand-packed fixed-layout struct behind
// the same function signatures a real protobuf version would use.
// When the .proto lands, only the *bodies* of kb_bridge_send_state()
// and kb_bridge_send_zone_transition() change — callers in
// kbd_sensor.c do not. Every wire struct below has a KB_WIRE_MAGIC
// + KB_WIRE_VERSION so the Go side can reject frames once it's
// switched to the real proto contract, instead of silently
// misparsing legacy bytes.

#ifndef KB_BRIDGE_H
#define KB_BRIDGE_H

#include <stdint.h>
#include <stddef.h>
#include "../../include/kb_scoring.h"

#define KB_WIRE_MAGIC    0x4B42  // "KB"
#define KB_WIRE_VERSION  3       // v3: added start_time_ns to ZoneTransition

#define KB_WIRE_MSG_PROCESS_STATE    1
#define KB_WIRE_MSG_ZONE_TRANSITION  2
#define KB_WIRE_MSG_PROCESS_EXIT     4
#define KB_WIRE_MSG_CONTAINMENT_CMD  5
// NOTE: msg_type 3 is double-booked on the Go side between the rules
// payload (kb-control-plane/internal/ipc/rules.go's msgTypeRules) and
// MsgTypeContainmentCmd (kb-control-plane/internal/ipc/types.go) — a
// pre-existing landmine, not touched here. 6 is the first genuinely
// unused value; see kb-control-plane/internal/ipc/sensitive_paths.go.
#define KB_WIRE_MSG_SENSITIVE_PATHS  6

#pragma pack(push, 1)
struct kb_wire_header {
    uint16_t magic;
    uint8_t  version;
    uint8_t  msg_type;
};

struct kb_wire_containment_cmd {
    struct kb_wire_header hdr;
    uint32_t pid;
    uint32_t level; // 0=None, 1=Cgroup, 2=Seccomp, 3=Namespace, 4=Terminate
    char reason[64];
};

struct kb_wire_process_exit {
    struct kb_wire_header hdr;
    uint32_t pid;
    uint64_t exit_time_ns;
    uint32_t exit_code;
};
#pragma pack(pop)

// ---- connection lifecycle ----

// Connect to a Unix domain socket at sock_path (e.g. "/var/run/kbd.sock").
// Retries with exponential backoff (starting at KB_BRIDGE_RETRY_MIN_MS,
// capped at KB_BRIDGE_RETRY_MAX_MS) until either it connects or
// max_attempts is exhausted. Pass max_attempts <= 0 to retry forever
// (blocks the caller — only use that on a dedicated bridge thread).
//
// Returns a connected fd (>= 0) on success, -1 on failure/timeout.
int kb_bridge_connect(const char *sock_path, int max_attempts);

// Non-blocking single-shot connect attempt, no retry/backoff. Useful
// for callers that want to manage their own reconnect loop (e.g. the
// heartbeat/reconnect thread described in kbd_sensor.c's wiring).
int kb_bridge_try_connect(const char *sock_path);

void kb_bridge_close(int fd);

// ---- sends ----
// Both return 0 on success, -1 on error (errno set; caller should
// treat this as "connection is dead" and reconnect, not retry-send).

int kb_bridge_send_state(int fd, const kb_process_state_t *s);

int kb_bridge_send_zone_transition(int fd, uint32_t pid, uint64_t start_time_ns,
                                    kb_zone_t from, kb_zone_t to,
                                    double score, uint64_t ts_ns);

int kb_bridge_send_process_exit(int fd, uint32_t pid, uint64_t exit_time_ns, uint32_t exit_code);

#define KB_BRIDGE_DEFAULT_SOCK   "/run/kb/kbd.sock"
#define KB_BRIDGE_RETRY_MIN_MS   100
#define KB_BRIDGE_RETRY_MAX_MS   5000

#endif // KB_BRIDGE_H