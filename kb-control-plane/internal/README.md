# KB Control Plane Internals

Private runtime implementation of the Kernel Borderlands (KB) Control Plane.

The `internal/` package contains the core services responsible for receiving behavioral telemetry from the Core Plane, maintaining runtime state, evaluating policies, coordinating enforcement, recording audit events, and exposing Control Plane services.

Packages inside this directory are implementation details and are **not intended to be imported outside the Control Plane**.

---

## Components

### controlplane/

Central orchestration component.

Responsibilities:

- Coordinates all internal subsystems
- Initializes runtime services
- Manages lifecycle
- Exposes gRPC services
- Receives events from IPC
- Dispatches work to Policy, Store, Audit, and Enforcement

---

### ipc/

Local IPC transport.

Responsibilities:

- Unix Domain Socket listener
- Wire protocol implementation
- Message framing
- Process State decoding
- Zone Transition decoding
- Event ingestion

---

### store/

Runtime behavioral state database.

Responsibilities:

- Process state storage
- Runtime lookups
- Behavioral zone tracking
- State synchronization
- In-memory behavioral model

---

### policy/

Behavioral policy engine.

Responsibilities:

- Evaluate behavioral state
- Match configured policies
- Produce security decisions
- Recommend enforcement actions

---

### enforcement/

Control Plane interface to the Enforcement Plane.

Responsibilities:

- Forward enforcement requests
- Verify delivery
- Track enforcement status
- Coordinate containment workflow

---

### audit/

Immutable behavioral audit subsystem.

Responsibilities:

- Record runtime decisions
- Hash-chain audit entries
- Tamper detection
- Behavioral event history

---

**`ssh/` was deleted from `kb-control-plane` in full (2026-08-30).** `kbd`'s
custom Wish-based SSH server was replaced by a real, independently-managed
`sshd` instance (`sshd@kb-operator.service`) with `ForceCommand` exec'ing
`kb-op/kb-tui` directly — `kbd` now has zero SSH code of any kind (no host
keys, no `authorized_keys` parsing, no PTY plumbing). See
`docs/development/core-control/control-plane-catalog.md` §2.11 for the
migration rationale and `docs/architecture/boot_sequence_spec.md` §3 for the
actual current unit/config.

---

## Runtime Flow

```text
   Core Plane            Operator
       │                     │ (SSH, sshd@kb-operator.service)
       ▼                     ▼
  IPC Receiver          ForceCommand → kb-tui (Rust)
       │                     │ (gRPC/IPC over /run/kb/kba.sock)
       ▼                     ▼
  Control Plane Runtime ◄────┘
       │
  ┌────┼────┐
  ▼    ▼    ▼
Store Policy Audit
  │    │
  └──┬─┘
     ▼
Enforcement
     │
     ▼
Enforcement Plane
```

---

## Design Principles

- Single responsibility per package
- Clear subsystem boundaries
- Low-latency execution
- In-memory runtime operations
- Deterministic policy evaluation
- Thread-safe concurrency
- Transport-independent business logic
- Minimal inter-package coupling
- Behavior-first architecture

---

## Package Structure

```
internal/
├── audit/           Immutable audit subsystem
├── controlplane/    Runtime orchestration and gRPC
├── enforcement/     Enforcement coordination
├── ipc/             Core ↔ Control IPC transport
├── policy/          Behavioral policy engine
└── store/           Runtime behavioral state store
```

`ssh/` no longer exists — see the note above the Runtime Flow diagram.

The `internal/` directory forms the operational core of the KB Control Plane, transforming behavioral telemetry from the Core Plane into coordinated runtime decisions, audit records, and enforcement requests while serving as the central orchestration layer between all downstream planes.