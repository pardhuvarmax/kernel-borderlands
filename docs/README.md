<img align="right" width="240" src="https://github.com/user-attachments/assets/ba4fdc53-151c-4477-b146-bc37b6859749" alt="Kernel Borderlands">

# Documentation

Kernel Borderlands is accompanied by a comprehensive collection of technical documentation located under the `docs/` directory. The documentation is organized by purpose, separating architectural design, feature implementations, development references, formal specifications, project resources, and historical reports.

Developers are strongly encouraged to familiarize themselves with the documentation before modifying the codebase. While the source code represents the implementation, the documentation defines the intended architecture, subsystem responsibilities, engineering decisions, development workflow, and long-term technical direction of the project.

---

## Documentation Index

### `docs/README.md`

The primary entry point for all project documentation. This document provides an overview of the documentation hierarchy and serves as the recommended starting point for contributors before exploring individual subsystems.

---

# Getting Started

Documentation required to prepare a development environment.

### `docs/getting-started/installation.md`

Provides complete installation instructions, environment preparation, dependency installation, platform-specific guidance, and the workflow required to build and run Kernel Borderlands.

### `docs/getting-started/requirements.md`

Defines software requirements, compiler versions, runtime dependencies, recommended hardware, supported operating systems, and required development tooling.

---

# Architecture

Documents describing how Kernel Borderlands is designed internally.

### `docs/architecture/boot_sequence_spec.md`

Describes the complete initialization sequence of the Kernel Borderlands platform, including subsystem startup order, dependency initialization, eBPF loader startup, daemon initialization, and runtime readiness.

### `docs/architecture/cross-kernel-portability.md`

Documents the CO-RE portability architecture used to support multiple Linux kernel versions through BTF, libbpf, runtime capability discovery, and feature fallback mechanisms.

### `docs/architecture/enabling-bpf-lsm.md`

Explains how Linux Security Module (LSM) support is enabled for Kernel Borderlands, including kernel configuration requirements, boot parameters, verifier considerations, and deployment guidance.

### `docs/architecture/hookpoints.md`

Documents the Linux kernel hook points instrumented by Kernel Borderlands, including telemetry collection, behavioral observation, and kernel event coverage.

### `docs/architecture/kbd-contracts.md`

Defines the event contract between `kb-core` and `kb-control-plane`, including event types, metadata conventions, payload expectations, and compatibility requirements.

---

# Features

Implementation documents describing individual Kernel Borderlands features.

### Included feature documentation

* Behavior Engine
* Dynamic Rules
* Critical Process Module (CPM)
* Critical Workload Protection (CWP)
* Gap Work Improvements
* In-Context Mitigation
* TLS Plaintext Monitoring
* Ray Integration

These documents describe feature architecture, implementation details, workflows, runtime behavior, design rationale, and future enhancements.

---

# Development

Internal engineering documentation intended for project contributors.

### `docs/development/developer-commands.md`

Quick reference containing the build, test, and execution commands for every Kernel Borderlands subsystem.

### `docs/development/core-control/`

Contains protocol specifications and implementation notes for communication between Kernel Borderlands core components, including IPC wiring, Unix Domain Socket bindings, wire protocol definitions, and structure updates.

### `docs/development/control-aads/`

Documents integration between the Kernel Borderlands control plane and Agentic AI Defense Swarm (AADS), including development notes and exfiltration detection architecture.

### `docs/development/adr/`

Contains Architecture Decision Records (ADRs) documenting significant engineering and architectural decisions made throughout the project's development.

---

# Specifications

Formal design specifications describing major subsystems and interfaces.

Current specifications include:

* Kernel Borderlands System Specification
* Operator Interface Specification
* eBPF Rate Limiting Design Specification
* Safety & Integrity Design Specification

These documents define subsystem requirements, interfaces, constraints, expected behavior, and implementation guidance.

---

# Reports

Historical engineering reports and milestone documentation.

Reports are organized by subsystem and development timeline, documenting implementation progress, design iterations, completed work, and engineering milestones throughout the project's evolution.

---

# Project

Project-level documentation and supporting resources.

### Included resources

* Team organization
* Contributor responsibilities
* Project whitepaper
* Project synopsis
* GitHub community resources

The project documentation provides the broader context behind Kernel Borderlands, including its research motivation, design philosophy, security model, architecture, and long-term roadmap.

---

Kernel Borderlands is designed as a long-term systems engineering project. The documentation is treated as a first-class component of the repository and evolves alongside the implementation. Contributors should consult the relevant documentation before introducing architectural changes or implementing new features to ensure consistency with the project's overall design principles.
