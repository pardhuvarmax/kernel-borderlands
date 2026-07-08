# Kernel Borderlands Core Engineering Records (`docs/core/`)

This directory houses core platform enhancement records, development cycle achievements, and session work reports for the Kernel Borderlands system.

---

## 📂 Document Catalog

### 1. [Boot Sequence & Daemon Lifecycle Specification](boot_sequence_spec.md)
* **Filename**: `boot_sequence_spec.md`
* **Purpose**: Comprehensive system boot-time timeline, socket ownership assignments, systemd service configuration, and fail-safe/recovery mechanisms for the daemon lifecycle.

### 2. [Ray Cluster Integration Walkthrough](ray_integration_walkthrough.md)
* **Filename**: `ray_integration_walkthrough.md`
* **Purpose**: Technical walkthrough and development worksheet for AADS swarm transition to Ray. Details transforming python agents to remote Ray Actors, remote actor message passing, orchestrator launch flows, and REST API diagnostics.
* **Lead Engineer**: Karthik (AADS Swarm Lead)

### 3. [Core v1 Enhancements](corev1-enhancements.md)
* **Filename**: `corev1-enhancements.md`
* **Purpose**: Documents the technical improvements, engine modifications, and performance optimizations implemented for Core v1.

### 4. [Engineering Work Reports](reports/README.md)
* **Subdirectory**: `reports/`
* **Purpose**: Houses chronological session and daily development cycle progress reports compiled by platform leads.
