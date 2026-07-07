# Kernel Borderlands Technical Specifications (`docs/specdocs/`)

This directory houses the authoritative technical specifications, design documents, and runtime contracts governing the Kernel Borderlands platform. Developers and contributors must consult these specifications when proposing changes to eBPF maps, protocol buffers, control plane storage models, or operator interfaces.

---

## 📂 Document Catalog

### 1. [Master System Specification](kernel_borderlands_specification.md)
* **Filename**: `kernel_borderlands_specification.md`
* **Purpose**: The master reference specification of the platform. Details directory maps, wire protocol version alignments, Behavior State Machine rules, EMA risk scoring, process lifecycle hooks, and privilege boundaries.

### 2. [eBPF Rate Limiting & Performance Spec](ebpf_rate_limiting_design_spec.md)
* **Filename**: `ebpf_rate_limiting_design_spec.md`
* **Purpose**: Details Ring 0 process-level (TGID) rate limiting. Covers hybrid state storage configurations (Task Local Storage on Linux 5.11+; composite LRU Hash Maps on Linux 5.8–5.10) and graceful degradation policies (bypass for Tier 1 events; counters and aggregation for Tier 2).

### 3. [Safety & Integrity Design Spec](safety_integrity_design_spec.md)
* **Filename**: `safety_integrity_design_spec.md`
* **Purpose**: Outlines active verification loops executed by the `kb-checker` Safety Engine. Covers cryptographically checking active kernel eBPF bytecode signatures, gRPC socket checks over `/run/kb/kbd.sock`, and Ray cluster container consensus audits.

### 4. [Operator Interfaces Spec](operator_interfaces_spec.md)
* **Filename**: `operator_interfaces_spec.md`
* **Purpose**: Outlines the design philosophy and workflows of the 4 operator surfaces:
  - **`kb-dashboard`**: Web visual console showing live process lineages (D3 force graphs).
  - **`kbctl`**: Go Cobra CLI for playbooks and CI pipelines.
  - **`kb-tui`**: Secure Wish SSH console (port 2222) for headless environments.
  - **`kb-mcp`**: JSON-RPC stdio protocol server for AI tool integration.

---

## 🛠️ Contribution Guardrails

* Any change modifying struct layouts (`ProcessState`, `ZoneTransition`) or the IPC magic (`0x4B42`) must update the **Master System Specification** and bump the protocol wire version.
* All new specifications must follow standard GFM (GitHub Flavored Markdown) formatting guidelines.
