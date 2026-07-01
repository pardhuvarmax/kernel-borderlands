# Userspace

The **Userspace** layer is the native runtime of KB Core. It receives telemetry from the eBPF layer, performs behavioral analysis, and communicates behavioral intelligence to the Go Control Plane.

The runtime is organized into modular subsystems with clearly defined responsibilities.

## Components

| Directory | Responsibility |
|-----------|----------------|
| `collectors/` | Receive and normalize telemetry from individual eBPF programs. |
| `sensor/` | Unified event ingestion and dispatch. |
| `behavior/` | Stateful behavioral analysis, scoring, and process intelligence. |
| `bridge/` | IPC between the native runtime and the Go Control Plane. |

## Design Principles

- Single responsibility per subsystem.
- Low-latency native processing.
- Stateful behavioral analysis.
- Clear separation between analytics and orchestration.
- Modular and extensible architecture.