# Sensor

The **Sensor** is the primary userspace entry point of the Kernel Borderlands telemetry pipeline. It is responsible for receiving unified telemetry from the eBPF instrumentation layer, coordinating event processing, and dispatching behavioral events to the native analytics engine.

Unlike individual telemetry collectors, the Sensor does not perform behavioral analysis or risk computation itself. Its responsibility is to orchestrate the flow of kernel events between the collection layer and the Behavior Engine while maintaining a lightweight, low-latency execution path.

---

## Responsibilities

- Load and initialize the unified eBPF sensor.
- Attach and manage all eBPF programs.
- Receive events from the eBPF ring buffer.
- Parse and normalize incoming telemetry.
- Construct unified behavioral events.
- Dispatch events to the Behavior Engine.
- Handle lifecycle management and graceful shutdown.

---

## Scope

The Sensor **does not**:

- Compute behavioral scores.
- Maintain process state.
- Perform anomaly detection.
- Classify behavioral zones.
- Make enforcement decisions.

Those responsibilities belong to the Behavior Engine and, ultimately, the Control Plane.

---

## Data Flow

```
Kernel
    │
    ▼
eBPF Programs
    │
    ▼
Unified Ring Buffer
    │
    ▼
Sensor
    │
    ▼
Behavior Engine
    │
    ▼
IPC Bridge
    │
    ▼
Go Control Plane
```

---

## Design Principles

- **Minimal processing** within the ingestion path.
- **Low-latency** event forwarding.
- **No behavioral intelligence** embedded in the Sensor.
- **Clear separation** between telemetry collection and behavioral analytics.
- **Single responsibility** as the entry point into the native userspace pipeline.

---

## Components

| Component | Description |
|-----------|-------------|
| `kbd_sensor.c` | Unified userspace sensor responsible for receiving and dispatching telemetry events. |

---

## Future Responsibilities

As Kernel Borderlands evolves, the Sensor may additionally support:

- Runtime configuration updates.
- Dynamic collector registration.
- Telemetry filtering.
- Collector health monitoring.
- Event batching and backpressure management.
- Performance instrumentation and telemetry statistics.

Its primary role, however, will remain the same: acting as the lightweight bridge between kernel telemetry collection and the native Behavior Engine.