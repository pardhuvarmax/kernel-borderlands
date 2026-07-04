# Process Store

In-memory behavioral state store for all tracked processes.

## Responsibilities

- Stores the latest Process State for every tracked PID
- Maintains current behavioral zones
- Provides fast lookup by PID
- Tracks process lifecycle
- Updates process state from IPC events
- Serves as the Control Plane's source of truth

## Stored Data

- Process metadata
- Behavioral dimension scores
- Composite score
- EMA score
- Behavioral zone
- Event counters
- Lifetime syscall entropy
- Timing information

## Properties

- In-memory storage
- O(1) average lookup
- Low-latency updates
- Thread-safe access
- No persistent storage
- Single source of truth for runtime process state

## Data Flow

```
IPC Receiver
      │
      ▼
Process Store
      │
 ┌────┼─────┐
 │    │     │
Policy Audit AADS
 │
Enforcement
```

## Directory

```
process.go      // Process state management
schema.go       // Shared state structures
store_test.go   // Store tests
```

The Process Store maintains the current behavioral model of the system.
It is the canonical runtime state shared across the Control Plane.