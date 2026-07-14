# Contributing to Kernel Borderlands

Thank you for your interest in contributing to **Kernel Borderlands**! This document outlines the standards, workflow, and procedures for contributing to our security observability and containment framework.

All contributors are expected to adhere to our project guidelines and standards to maintain system integrity and stability.

---

## 1. Code Contribution Process

### Step 1: Issue Tracking
Before starting any development work, ensure there is an open issue describing the feature, bug, or improvement. 
* Review existing issues to prevent duplicate work.
* For major architectural modifications, comment on the issue or submit an Architectural Decision Record (ADR) draft for review before writing code.

### Step 2: Branching Strategy
* Always create feature or bugfix branches from the `main` branch.
* Use a descriptive branch naming convention:
  * Features: `feat/short-description`
  * Bug fixes: `fix/short-description`
  * Documentation: `docs/short-description`
  * Refactoring: `refactor/short-description`

### Step 3: Pull Requests
When submitting a Pull Request (PR):
1. Provide a clear description of the problem solved and the implementation details.
2. Link the PR to the relevant tracked issue.
3. Ensure the project builds successfully and passes all automated test suites.
4. Ensure documentation is kept in sync with code changes.

---

## 2. Technical Stack & Subsystem Coding Standards

Kernel Borderlands is composed of multiple subsystems with strict boundaries. Code modifications must adhere to language-specific standards:

### A. Kernel Instrumentation (`kb-core` — eBPF C)
* **Verifier Compatibility**: All eBPF programs must be verifier-safe. Avoid infinite loops, ensure all array/map accesses are bound-checked, and use compiler annotations like `#pragma unroll` for loops.
* **Compatibility (CO-RE)**: Write portable eBPF using Compile Once – Run Everywhere conventions. Maintain helper compatibility with target kernel versions.
* **Shared Structs**: Structs shared across the boundary between kernel-space and user-space loader must be strictly packed (`__attribute__((packed))`).

### B. Control Plane (`kb-control-plane` — Go)
* **Wire Alignment**: Telemetry structure definitions in Go must be binary-aligned with the packed C structures defined in `kb-core` to ensure correct serialization.
* **Concurrency Safety**: Telemetry streams are processed concurrently. Ensure data access uses appropriate synchronization (e.g., mutexes, channels, atomic operations) to prevent data races.

### C. Watchdog Monitor (`kb-checker` — Rust)
* **Statelessness**: The watchdog must remain stateless and have zero network dependencies. Do not integrate external databases or API layers.
* **Error Handling**: Implement strict error handling and recovery mechanisms; panics should be avoided in critical monitoring loops.

### D. Adaptive Agent Swarm (`kb-aads` — Python)
* **Type Annotations**: All Python modules should use standard PEP 484 type hinting.
* **Performance**: Operations dealing with IPC streams must optimize resource usage to maintain sub-millisecond telemetry processing times.

---

## 3. Testing Requirements

No code change will be accepted without verification. Contributors must run and write tests:

* **Unit Testing**: Implement test cases for new libraries, parser modules, and state transitions. For example, any updates to the rules engine should be verified in `kb-core/tests/test_behavior.c`.
* **Integration Testing**: Verify the interaction between the eBPF sensor, Go control plane, and user-space IPC bridge.
* **Performance Testing**: Measure CPU overhead and event processing latency when adding new eBPF tracepoints or LSM hooks to ensure system overhead remains negligible.

---

## 4. Documentation Guidelines

Our documentation (located under `docs/`) is the canonical source of truth for the project.
* **Specification Updates**: If a pull request modifies a public API, database schema, IPC protocol, or wire contract, the author must update the corresponding specification file under `docs/specifications/` or `docs/architecture/`.
* **ADRs**: Architectural changes must be documented via Architectural Decision Records (ADRs) under `docs/development/adr/` before implementation.
