# Bridge

The **Bridge** is the communication layer between the native Behavior Engine and the Go Control Plane. Its responsibility is to transport behavioral intelligence generated within the native userspace runtime to higher-level orchestration services while maintaining low latency, reliability, and a well-defined interface between both subsystems.

Unlike the Sensor or Collectors, the Bridge does not observe kernel activity or perform behavioral analysis. Instead, it serves as the transport mechanism through which computed behavioral state, risk assessments, and significant lifecycle events are delivered to the Control Plane.

The Bridge establishes a clear architectural boundary: the native runtime is responsible for generating behavioral intelligence, while the Go daemon is responsible for consuming that intelligence to perform persistence, policy evaluation, auditing, enforcement, and external integrations.

---

## Responsibilities

- Establish communication with the Go Control Plane.
- Serialize and transmit behavioral messages.
- Deliver process state updates.
- Deliver behavioral zone transitions.
- Deliver raw behavioral events when required.
- Handle connection lifecycle and reconnection.
- Provide reliable local IPC between native and managed components.

---

## Data Exchanged

The Bridge is expected to transport three primary categories of information:

### Behavioral Events

Raw telemetry events produced by the Sensor after normalization.

Examples include:

- Process lifecycle events
- Privilege transitions
- File access events
- Network activity
- Memory mapping events
- System call telemetry

---

### Behavioral State

Continuously updated process state produced by the Behavior Engine.

Typical information includes:

- Process identity
- Behavioral metrics
- Dimension scores
- Composite risk score
- EMA score
- Behavioral zone
- Historical counters
- Timing information

---

### Zone Transitions

High-priority behavioral notifications indicating changes in process risk classification.

Examples include:

```
SAFE → SUSPICIOUS
SUSPICIOUS → BORDERLANDS
BORDERLANDS → SAFE
```

These transitions allow the Control Plane to react immediately without continuously polling process state.

---

## Data Flow

```
Kernel
    │
    ▼
eBPF Programs
    │
    ▼
Collectors
    │
    ▼
Sensor
    │
    ▼
Behavior Engine
    │
    ▼
Bridge
    │
    ▼
Go Control Plane
```

---

## Design Principles

- Low-latency local communication.
- Clear separation between analytics and orchestration.
- No behavioral computation within the Bridge.
- Stateless message transport.
- Stable communication interface between native and Go components.
- Extensible message protocol for future capabilities.

---

## Planned IPC

The initial implementation will utilize **Unix Domain Sockets** for local inter-process communication.

This approach provides:

- Low latency
- Minimal overhead
- Simple deployment
- Efficient local communication
- Straightforward integration with the Go Control Plane

The Go daemon will consume these messages and expose them through higher-level interfaces such as REST and gRPC without requiring the native runtime to directly depend on those frameworks.

---

## Feature Sheet

### Current Features

-    Unix Domain Socket (UDS) IPC transport
-    Lightweight binary wire protocol
-    Length-prefixed message framing
-    Wire protocol versioning
-    ProcessState message transport
-    ZoneTransition message transport
-    Automatic connection establishment
-    Automatic reconnection on disconnect
-    Exponential backoff retry strategy
-    Reliable blocking writes with partial-write handling
-    PID reuse protection (start_time_ns validation)
-    Low-latency userspace IPC
-    Minimal-copy message transport
-    Transport abstraction between Core and Control Planes
-    Extensible wire protocol foundation

### Future Expansion

As Kernel Borderlands evolves, the Bridge transport layer may be extended with additional capabilities while maintaining compatibility with the existing IPC architecture.

Planned enhancements include:

-    Protocol Buffers (protobuf) serialization
-    Versioned protobuf schemas
-    Event batching and coalescing
-    Message prioritization
-    Flow control and backpressure handling
-    Connection health monitoring
-    Transport and telemetry statistics
-    Secure authenticated communication
-    Optional message compression
-    Capability negotiation
-    Stream multiplexing
-    Zero-copy optimizations where applicable
-    Delivery acknowledgements for critical messages
-    High-availability and failover support
-    Multi-channel transport support

Regardless of implementation details, the Bridge will remain responsible solely for communication. All behavioral intelligence originates within the Behavior Engine, while all operational decisions remain within the Control Plane.
