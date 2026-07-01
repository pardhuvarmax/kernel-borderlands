# Collectors

The **Collectors** are responsible for acquiring raw kernel telemetry from the eBPF instrumentation layer and transforming it into a consistent stream of behavioral events for the Sensor. Each collector represents a specific behavioral dimension of the operating system and acts as the userspace counterpart to its corresponding eBPF program.

Collectors are intentionally lightweight. Their primary purpose is to receive, parse, and normalize telemetry—not to interpret it. They do not maintain behavioral state, compute risk scores, or perform anomaly detection. Instead, they provide structured observations that are consumed by the Behavior Engine for higher-level behavioral analysis.

---

## Responsibilities

- Interface with individual eBPF programs.
- Receive telemetry through ring buffers or perf buffers.
- Parse and validate kernel event data.
- Normalize telemetry into a common event representation.
- Forward events to the Sensor for behavioral processing.
- Handle collector-specific initialization and cleanup.

---

## Current Collectors

| Collector | Behavioral Dimension |
|-----------|----------------------|
| `kb_process.c` | Process lifecycle (fork, exec, exit) |
| `kb_syscall.c` | System call activity and entropy telemetry |
| `kb_privilege.c` | Privilege transitions (UID, GID, capabilities) |
| `kb_file.c` | File system activity and sensitive file access |
| `kb_network.c` | Network connections and socket behavior |
| `kb_memory.c` | Memory mappings and execution permissions |

Each collector is paired with a dedicated eBPF program under `ebpf/`, forming a one-to-one instrumentation pipeline.

---

## Design Philosophy

Collectors should remain **stateless** whenever possible.

Their responsibilities end once telemetry has been collected and normalized. Any behavioral reasoning—including historical analysis, anomaly detection, scoring, or zone classification—is intentionally delegated to the Behavior Engine.

This separation keeps collectors simple, reusable, and focused solely on telemetry acquisition.

---

## Data Flow

```
Kernel Activity
        │
        ▼
eBPF Instrumentation
        │
        ▼
Individual Collector
        │
        ▼
Unified Sensor
        │
        ▼
Behavior Engine
```

---

## Design Principles

- Single responsibility for each behavioral dimension.
- Minimal processing before behavioral analysis.
- Consistent event normalization across collectors.
- Low-overhead telemetry acquisition.
- Independent development and testing of each collector.
- No behavioral state or scoring logic.

---

## Future Expansion

The collector architecture is designed to accommodate additional behavioral dimensions without modifying the existing pipeline. Future collectors may include:

- Module and kernel object activity
- Namespace and container events
- cgroup lifecycle
- IPC mechanisms
- Scheduler behavior
- Credential and capability changes
- Security framework (LSM) events
- eBPF program lifecycle monitoring

Each new collector should continue to follow the same architectural principle: **collect telemetry, normalize events, and delegate behavioral intelligence to the Behavior Engine.**