# Dynamic Rule Delivery System

**Status:** Completed — implemented in `kb-control-plane/internal/ipc/rules.go` and `kb-control-plane/config/rules.yaml`.

**Correction, 2026-08-30**: this doc's "Completed" status was accurate for the serialization/parsing pieces (B and C below) but not for the actual delivery — `SendRulesPayload` was fully implemented and unit-tested but had **zero production call sites**; nothing ever invoked it, so editing `rules.yaml` had no effect on a running sensor despite this doc's §1 architecture diagram showing it happening. `kbd_sensor.c` itself carried an honest comment documenting this exact gap at its `read_rules_from_bridge()` call site. Now genuinely wired: `ipc.Listener.pushConnectTimeFrames` calls `SendRulesPayload` on every new sensor connection, configurable via `kbd --rules` (default `config/rules.yaml`). One correctness note worth preserving here since it's easy to get backwards: **send order matters** — the C sensor's connect-time handshake reads the rules frame first, then the sensitive-paths frame second, and only the second read has a fallback for "the wrong frame arrived here." Sending sensitive-paths before rules silently corrupts the connection's later framing. Regression test guarding this exact ordering: `TestPushConnectTimeFrames_RulesSentBeforeSensitivePaths` (`internal/ipc/rules_push_test.go`).

We have designed and implemented a **Dynamic Rule Delivery System** to ensure Kernel Borderlands is never blind to new attacks. Analysts can now add or edit attack-chain rules in a human-readable YAML configuration file, which the Go control plane dynamically parses, serializes into a packed binary format, and delivers to the C sensor at startup or upon connection.

---

## 1. Architecture Flow

```mermaid
sequenceDiagram
    participant Operator as YAML Configuration
    participant GoCP as Go Control Plane
    participant Bridge as Unix Domain Socket
    participant CSensor as C Sensor (Userspace)

    Operator->>GoCP: rules.yaml (Adds/Edits rules)
    Note over GoCP: Parses YAML strings<br/>& maps to internal uint64/uint32 values
    CSensor->>Bridge: Connects to socket
    Bridge->>GoCP: Accept connection
    GoCP->>Bridge: Write binary serialized rules payload
    CSensor->>Bridge: Read & parse header (magic & v3)
    CSensor->>CSensor: Load rules directly into memory table
    Note over CSensor: Sensor switches to dynamic rules evaluation
```

---

## 2. Implementation Components

### A. Configuration Spec (`rules.yaml`)
Defined in [rules.yaml](file:///home/emergence/Desktop/kernel-borderlands/kb-control-plane/config/rules.yaml). It lists both generic and signature-like rules:
```yaml
rules:
  - name: reverse_shell_compromised
    description: "Outbound connection followed by shell execution"
    required_flags:
      - KB_EV_OUTBOUND_CONNECT
      - KB_EV_SPAWNED_SHELL
    sequence:
      - KB_SEQ_OUTBOUND_CONNECT
      - KB_SEQ_EXEC_SHELL
    window_seconds: 60
    target_state: KB_STATE_COMPROMISED
    reason: KB_REASON_REVERSE_SHELL_CHAIN
    min_source_state: KB_STATE_BORDERLANDS
```

### B. Go Serialization & Transport (`rules.go`)
Implemented in [rules.go](file:///home/emergence/Desktop/kernel-borderlands/kb-control-plane/internal/ipc/rules.go). 
- Maps YAML strings to internal integer flags (e.g. `KB_EV_OUTBOUND_CONNECT` $\rightarrow$ `1<<32`).
- Packs the rule properties into a `KBWireAttackRule` structure matching the memory layout of C's `kb_wire_attack_rule`.
- Serializes and writes a framed payload to the socket upon sensor connection.

### C. C Memory Allocation & Handshake (`kb_rules.c` / `kbd_sensor.c`)
- **Handshake**: At startup or connection refresh in [kbd_sensor.c](file:///home/emergence/Desktop/kernel-borderlands/kb-core/userspace/sensor/kbd_sensor.c), the C sensor performs a blocking read on the Unix socket to retrieve the rules payload.
- **Dynamic Load**: Copies the wire structs directly into static arrays inside [kb_rules.c](file:///home/emergence/Desktop/kernel-borderlands/kb-core/userspace/behavior/kb_rules.c) and resolves pointer assignments, dynamically substituting the compiled-in rules.
- **Fallback**: If the Go daemon is down or fails to send rules, the sensor transparently falls back to the default compiled-in rules, ensuring high availability.

---

## 3. Validation

- **Go Unit Tests**: Added [rules_test.go](file:///home/emergence/Desktop/kernel-borderlands/kb-control-plane/internal/ipc/rules_test.go) which simulates connection handshakes, verifies YAML parsing, and asserts exact byte-alignment sizes matching C's layout.
  ```bash
  $ go test ./...
  ok  	github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc	0.019s
  ```
- **C Compilation**: Built successfully with zero errors:
  ```bash
  $ make
  clang -g -Wall -I.output ... -o build/kbd_sensor
  ```
