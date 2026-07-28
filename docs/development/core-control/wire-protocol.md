# KB Wire Protocol — kbd_sensor → kbd daemon

**Known stale beyond this pass's fix (flagging, not fully correcting here — out of
scope for this pass, worth its own rewrite):** `version = 1` below is outdated —
`kb_bridge.h`'s current `KB_WIRE_VERSION` is `3`, `ProcessState` doesn't include the
`start_time_ns` field the v3 bump added (see `wire-update.md`), and this doc only
documents `msg_type` 1/2 — it's silent on `ContainmentCmd` (5), `ProcessExit` (4), and
`SensitivePaths` (6), all of which exist in `kb_bridge.h` today. Only the Socket Path
section below has been corrected as part of this pass (it was directly affected by the
kbd.sock/kbct.sock split); the rest predates that and was already out of date before it.

**format :** 

```
[4 bytes LE length prefix][payload bytes]

Payload types:
  msg_type=1 → kb_wire_process_state struct
  msg_type=2 → kb_wire_zone_transition struct

Both start with kb_wire_header:
  uint16 magic   = 0x4B42 ("KB")
  uint8  version = 1
  uint8  msg_type
```

## Framing
Every message: [4-byte LE uint32 length][payload of exactly that length]
Length covers payload only, not the 4-byte prefix.

## Magic + Version
All payloads start with:
  bytes [0:1] = 0x4B, 0x42  ("KB")
  byte  [2]   = 0x01         (version)
  byte  [3]   = msg_type

## msg_type = 1 — ProcessState (sent every 20 events per PID)
Packed struct, all little-endian:
  uint16 magic
  uint8  version
  uint8  msg_type = 1
  uint32 pid
  uint32 ppid
  uint32 uid
  char   comm[16]
  uint64 start_time_ns
  uint64 last_updated_ns
  double dim_score[6]      // [process, syscall, privilege, file, network, memory]
  double composite_score
  double ema_score
  uint32 zone              // 0=SAFE 1=SUSPICIOUS 2=BORDERLANDS
  uint32 event_count
Total: 2+1+1+4+4+4+16+8+8+(6*8)+8+8+4+4 = 122 bytes

## msg_type = 2 — ZoneTransition (sent on every zone change)
Packed struct, all little-endian:
  uint16 magic
  uint8  version
  uint8  msg_type = 2
  uint32 pid
  uint32 from_zone
  uint32 to_zone
  double score
  uint64 ts_ns
Total: 2+1+1+4+4+4+8+8 = 32 bytes

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

## Socket Path
  /run/kb/kbd.sock  (not /var/run/kbd.sock — corrected)
  Telemetry only (this doc's scope: ProcessState + ZoneTransition, both
  sensor -> kbd). As of the kbd.sock/kbct.sock split (see
  docs/development/core-control/control-plane-catalog.md §5.3),
  kbd_sensor holds a SECOND, separate long-lived connection to
  /run/kb/kbct.sock for the reverse direction (containment commands,
  sensitive-path pushes) — out of this doc's scope by its own title, but
  worth knowing this is no longer the only connection kbd_sensor holds.
  On disconnect: kbd_sensor reconnects automatically on next event.
  Ignores SIGPIPE (signal(SIGPIPE, SIG_IGN) in kbd_sensor.c's main())
  rather than relying on a delivered EPIPE-triggering signal to reconnect
  — a write() to a closed connection now just returns -1/EPIPE like any
  other error instead of killing the process, and reconnect logic (via
  bridge_ensure_connected()) picks it up from there.

- refer these files :
    - [bridge files](../../kb-core/userspace/bridge)
    - [scoring engine](../../kb-core/userspace/behavior)
    - [scoring header](../../kb-core/include/kb_scoring.h)

