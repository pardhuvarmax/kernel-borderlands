# KB Wire Protocol — kbd_sensor ↔ kbd daemon

**Rewritten in full** to match `kb-core/userspace/bridge/kb_bridge.h`/`.c` and
`kb-core/userspace/sensor/kbd_sensor.c` as of `KB_WIRE_VERSION = 3`. Supersedes
the previous version=1, msg_type 1/2-only draft of this doc.

**format :**

```
[4 bytes LE length prefix][payload bytes]

Payload types:
  msg_type=1 → kb_wire_process_state       (sensor → kbd)
  msg_type=2 → kb_wire_zone_transition      (sensor → kbd)
  msg_type=4 → kb_wire_process_exit         (sensor → kbd)
  msg_type=5 → kb_wire_containment_cmd      (kbd → sensor)
  msg_type=6 → sensitive-paths registry     (kbd → sensor)
  msg_type=7 → CPM protected-exec registry  (kbd → sensor, no sender yet)
  msg_type=8 → CWP protected-workload registry (kbd → sensor, no sender yet)
  msg_type=9 → net flow sample (sensor → kbd, exfiltration detection)

Every payload starts with kb_wire_header:
  uint16 magic   = 0x4B42 ("KB")
  uint8  version = 3
  uint8  msg_type
```

**msg_type = 3 is double-booked, not free**: the Go side already uses it in
two places — `kb-control-plane/internal/ipc/rules.go`'s rules payload and,
separately, an older `MsgTypeContainmentCmd` definition in
`kb-control-plane/internal/ipc/types.go`. This is a pre-existing landmine in
the Go source, not touched by this doc; `6` was the first genuinely unused
value going forward (see `kb-control-plane/internal/ipc/sensitive_paths.go`).

## Framing
Every message: `[4-byte LE uint32 length][payload of exactly that length]`.
Length covers payload only, not the 4-byte prefix.

## Magic + Version
All payloads start with `kb_wire_header` (4 bytes):
  bytes [0:1] = 0x4B, 0x42  ("KB")
  byte  [2]   = 0x03         (version — `KB_WIRE_VERSION` in `kb_bridge.h`)
  byte  [3]   = msg_type

## msg_type = 1 — ProcessState (sensor → kbd, sent every 20 events per PID)
Packed struct (`kb-core/userspace/bridge/kb_bridge.c`'s `kb_wire_process_state`), all little-endian:
```
kb_wire_header hdr        4
uint32 pid                4
uint32 ppid                4
uint32 uid                 4
char   comm[16]           16
uint64 start_time_ns       8
uint64 last_updated_ns     8
double dim_score[6]        48   // [process, syscall, privilege, file, network, memory]
double composite_score      8
double ema_score            8
double syscall_entropy_lifetime  8   // advisory only, not part of composite/ema
uint32 zone                 4   // 0=SAFE 1=SUSPICIOUS 2=BORDERLANDS
uint32 event_count          4
```
Total: 128 bytes — matches the 128B `ProcessState` figure in the root `CLAUDE.md`
and `docs/architecture/kbd-contracts.md`.

## msg_type = 2 — ZoneTransition (sensor → kbd, sent on every zone change)
Packed struct (`kb_wire_zone_transition`), all little-endian:
```
kb_wire_header hdr        4
uint32 pid                 4
uint64 start_time_ns       8   // pid-reuse guard — added in the v3 wire bump;
                                // enforcement should verify this still matches
                                // the pid's known start time before acting, since
                                // pids get reused and a stale/reused pid must not
                                // get contained by mistake.
uint32 from_zone            4
uint32 to_zone               4
double score                8
uint64 ts_ns                 8
```
Total: 40 bytes — matches the 40B `ZoneTransition` figure in the root `CLAUDE.md`.

## msg_type = 4 — ProcessExit (sensor → kbd)
Packed struct (`kb_wire_process_exit`, `kb_bridge.h`), all little-endian:
```
kb_wire_header hdr        4
uint32 pid                 4
uint64 exit_time_ns        8
uint32 exit_code           4
```
Total: 20 bytes. Triggers immediate L1/L2 eviction on the Go side (see
`CHANGELOG.md`'s Process Exit Lifecycle entry) to close a PID-reuse gap.

## msg_type = 5 — ContainmentCmd (kbd → sensor, over `/run/kb/kbct.sock`)
Packed struct (`kb_wire_containment_cmd`, `kb_bridge.h`), all little-endian:
```
kb_wire_header hdr        4
uint32 pid                 4
uint32 level                4   // 0=None, 1=Cgroup, 2=Seccomp, 3=Namespace, 4=Terminate
char   reason[64]          64
```
Total: 76 bytes. `reason` is printed with `%.64s` on the C side to avoid
reading past a non-NUL-terminated string that crossed the process boundary.

## msg_type = 6 — SensitivePaths registry push (kbd → sensor)
Not a single fixed struct — a header-count-entries frame
(`apply_sensitive_paths_frame()` in `kbd_sensor.c`):
```
kb_wire_header hdr        4
uint32 count                4
char   path[64] * count    64 * count   // NUL-padded, zero-filled past the terminator
```
Merged additively into the live `kb_sensitive_paths` BPF map on top of the
compiled-in floor — the floor can never be narrowed via this push. Sent once,
at sensor connect time; not a live-reload channel.

## msg_type = 7 — CPM protected-exec registry (kbd → sensor)
Same frame shape as msg_type 6 (`kb_wire_header` + `uint32 count` + `count *`
64-byte zero-padded path keys) — see `docs/features/CPM.md` §7.4.
**C-side receiver exists; `kb-control-plane` has no sender for this yet** —
in practice no frame with this msg_type is ever sent today. Open follow-up,
tracked in `kb-core/README.md`.

## msg_type = 8 — CWP protected-workload registry (kbd → sensor)
```
kb_wire_header hdr        4
uint32 count                4
entry[count]:
  char    path[64]          64   // zero-padded
  uint8   identity_tier      1   // 0=path, 1=hash
  uint8   expected_sha256[32] 32  // zero if identity_tier=path
```
Per-entry size 97 bytes (`KB_CWP_WORKLOAD_ENTRY_SIZE`). Deliberately omits
`policy_id`/`owner_team`/`justification` (§6.2 of `docs/features/CWP.md`) —
those only feed the severity-escalated alerting pipeline, not sensor-side
enforcement. **C-side receiver exists; `kb-control-plane` has no sender for
this yet**, same open-follow-up status as msg_type 7.

## msg_type = 9 — NetFlow (sensor → kbd, sent per KB_EVT_NETWORK_CONNECT)
Packed struct (`kb_wire_net_flow`, `kb_bridge.h`), all little-endian:
```
kb_wire_header hdr        4
uint32 pid                 4
uint32 daddr                4   // destination IPv4, network byte order
uint16 dport                 2   // destination port, host byte order
uint16 _reserved              2
uint64 ts_ns                   8
```
Total: 22 bytes. Sent from `kbd_sensor.c`'s userspace `handle_event()`
(NOT the eBPF program — added 2026-09-07 for
`docs/development/control-aads/dev-exfiltration-detection.md`'s
out-of-band beaconing/exfiltration detector, `kb-control-plane/internal/
detection/exfil.go`). Carries no byte-count field — `connect()` doesn't
have one; see that doc's fidelity-limitation note.

## Dimension Index Map
  0 = KB_DIM_PROCESS    weight=0.20
  1 = KB_DIM_SYSCALL    weight=0.25
  2 = KB_DIM_PRIVILEGE  weight=0.20
  3 = KB_DIM_FILE       weight=0.10
  4 = KB_DIM_NETWORK    weight=0.10
  5 = KB_DIM_MEMORY     weight=0.15

## Zone Values
  0 = SAFE
  1 = SUSPICIOUS
  2 = BORDERLANDS

## Socket Paths
  /run/kb/kbd.sock   Telemetry only, sensor → kbd (msg_type 1, 2, 4).
  /run/kb/kbct.sock  Control only, kbd → sensor (msg_type 5, 6, 7, 8) — split
                     from kbd.sock so a telemetry burst can never stall or kill
                     containment delivery. See
                     `docs/development/core-control/control-plane-catalog.md`
                     §5.3 and `kb-control-plane/internal/ipc/sockets.go`'s
                     `SocketIPC` comment.

  On disconnect: kbd_sensor reconnects automatically on next event.
  Ignores SIGPIPE (`signal(SIGPIPE, SIG_IGN)` in `kbd_sensor.c`'s `main()`)
  rather than relying on a delivered EPIPE-triggering signal to reconnect —
  a write() to a closed connection now just returns -1/EPIPE like any
  other error instead of killing the process, and reconnect logic (via
  `bridge_ensure_connected()`) picks it up from there.

  Connect-time reads (rules/sensitive-paths pushes) use a 2s `SO_RCVTIMEO`
  (`KB_BRIDGE_CONNECT_READ_TIMEOUT_SEC` / `connect_once()` in `kb_bridge.c`)
  so a push that never arrives fails fast into the compiled-in-defaults
  fallback instead of hanging the sensor at startup.

- refer these files :
    - [bridge files](../../kb-core/userspace/bridge)
    - [scoring engine](../../kb-core/userspace/behavior)
    - [scoring header](../../kb-core/include/kb_scoring.h)
