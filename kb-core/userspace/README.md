# Userspace Subsystems

The userspace runtime of `kb-core` is written in C for maximum performance and low memory footprint. It manages the eBPF skeleton lifecycle, handles event polling, parses binary symbol tables, and communicates state to the Go Control Plane.

---

## Directory Components

### 1. `sensor/` (Unified Event Loader)
*   **Daemon (`kbd_sensor.c`)**: Serves as the primary userspace daemon. Polls the `kb_events` Ring Buffer, executes backfill proc scans for running processes, and prints formatted logs.
*   **ELF offset Resolver (`find_elf_symbol_offset`)**: Parses dynamic ELF headers (`.symtab`/`.dynsym` sections) to resolve uprobe offsets for OpenSSL, Go, GnuTLS, and NSS without requiring external linking dependencies.
*   **Go TLS Attacher**: Monitors execution events to dynamically parse `/proc/[pid]/exe` and attach uprobes on-the-fly to statically compiled Go runtimes.

### 2. `behavior/` (Stateful Behavior Engine)
*   **`kb_behavior.c`**: Evaluates active processes against sequences and evidence flags.
*   **`kb_rules.c`**: Manages the local rule table and handles dynamic rules loading.
*   **`kb_scoring.c`**: Computes advisory composite threat indicators and EMA scores.
*   **`kb_evidence.c`**: Implements state storage for evidence flags and sequence logs.

### 3. `bridge/` (IPC Unix Socket Client)
*   **`kb_bridge.c`**: Implements connection heartbeats and binary serialization to forward process states and zone transitions to the Go Control Plane over `/tmp/kbd.sock`. Handles binary packing and headers.

---

## Performance Considerations
*   **Zero Allocations in Event Loop**: Event frames are read directly from the ring buffer memory pool, avoiding heap allocations on the hot path.
*   **Asynchronous Processing**: Complex math and disk operations are delegated to the Go Control Plane, maintaining a low-latency thread context in the sensor.