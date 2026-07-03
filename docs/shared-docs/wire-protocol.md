# KB Wire Protocol — kbd_sensor → kbd daemon

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
  /var/run/kbd.sock
  Single long-lived connection from kbd_sensor.
  On disconnect: kbd_sensor reconnects automatically on next event.
  On kbd restart: kbd_sensor detects EPIPE and reconnects.

- refer these files :
    - [bridge files](../../kb-core/userspace/bridge)
    - [scoring engine](../../kb-core/userspace/behavior)
    - [scoring header](../../kb-core/include/kb_scoring.h)

