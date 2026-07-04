# IPC (Unix Domain Socket Transport)

Local high-performance IPC layer connecting the KB Core Plane and KB Control Plane.

## Responsibilities

- Accepts incoming Unix Domain Socket (UDS) connections from the Core Plane
- Receives length-prefixed binary messages from `kb_bridge`
- Validates wire protocol (magic, version, message type)
- Deserializes Process State and Zone Transition messages
- Converts wire payloads into internal Go structures
- Delivers decoded events to the Control Plane event pipeline
- Detects malformed or incompatible protocol frames
- Supports protocol versioning for forward compatibility

## Transport Properties

- Unix Domain Socket (AF_UNIX)
- Local host only (no TCP/IP stack)
- Length-prefixed binary framing
- Little-endian wire format
- Versioned protocol
- Automatic reconnect handled by Core Plane
- Zero network exposure

## Message Types

### Process State

Complete behavioral snapshot of a tracked process.

Contains:

- Process metadata
- Behavioral dimension scores
- Composite score
- EMA score
- Behavioral zone
- Lifetime syscall entropy
- Event counters
- Timing metadata

### Zone Transition

Emitted whenever a process changes behavioral zone.

Contains:

- PID
- Process start time (PID reuse protection)
- Previous zone
- New zone
- Trigger score
- Transition timestamp

## Directory

```
listener.go     // UDS listener and connection lifecycle
wire.go         // Wire protocol parsing and serialization
wire_test.go    // Protocol and framing tests
readme.md
```

## Design Goals

- Ultra-low latency local communication
- Stable binary protocol
- Strict protocol validation
- Minimal allocations
- Backward-compatible versioning
- Clear separation between transport and business logic

The IPC subsystem is transport-only. It performs no behavioral analysis,
policy evaluation, enforcement, or AI inference. Its sole responsibility is
to reliably move telemetry from the Core Plane into the Control Plane.

