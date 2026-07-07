# Kernel Borderlands Technical Work Report

* **Date**: July 7, 2026
* **Lead Engineer**: K. Pardhu (Systems & Security Lead)
* **Role**: Systems Architecture, Linux Kernel Development, & Safety Integrity Coordinator

---

## 1. Executive Summary

Today's engineering effort focused on consolidating the Kernel Borderlands operator interfaces under a unified directory structure, isolating technical specification papers into a dedicated specs folder, syncing the off-tree GitHub wiki repository, updating the public project website, and appending permanent developer guidelines to the CLI memory guidelines.

No modifications were made to the core eBPF C loader (`kb-core`), the Go control daemon runtime (`kb-control-plane`), or the Python agent swarm (`kb-aads`). All updates were concentrated on technical specs, directory restructuring, documentation, and metadata files to ensure design consistency and prevent engineering drift.

---

## 2. Completed Work Items

### A. Subsystem Nesting & Operator Consolidation
* Created the parent directory `kb-op/` to house the administrative operator interfaces.
* Relocated `kb-tui/` and `kb-dashboard/` under `kb-op/`.
* Created comprehensive subsystem documentation:
  * [kb-op/README.md](../../kb-op/README.md) — Operator Suite topology map and Mermaid structure.
  * [kb-op/kbctl/README.md](../../kb-op/kbctl/README.md) — CLI client usage and dynamic playbook controls.
* Resolved a Mermaid diagram parser error inside the operator README by quoting node labels and correcting subgraph naming schemas.

### B. Specification Refactoring (`docs/specdocs/`)
* Isolated platform specs from general markdown files by creating the `docs/specdocs/` folder.
* Relocated the following specifications:
  * `kernel_borderlands_specification.md` (Master Specification)
  * `safety_integrity_design_spec.md` (Safety Engine Audits)
  * `ebpf_rate_limiting_design_spec.md` (Ring 0 Telemetry Throttling)
* Authored a new specification document:
  * [docs/specdocs/operator_interfaces_spec.md](../specdocs/operator_interfaces_spec.md) — Outlines the four operator surfaces (Dashboard, CLI, TUI, MCP) and details the rationale for using four distinct interfaces to provide graceful access degradation.
* Created a folder directory catalog index at [docs/specdocs/README.md](../specdocs/README.md).

### C. Project Website Updates (`docs/index.html`)
* Updated the project website [docs/index.html](../index.html) to display the Model Context Protocol (MCP) server under catalog index `S04c`.
* Updated the Operator Interfaces section grid, inserting **Surface 04 (kb-mcp)** styled cards, capabilities bullet lists, and animations.
* Aligned downstream catalog numbering (shifting Subsequent Subsystems to `S05`, `S06`, etc.).

### D. Off-Tree Wiki Sync (`kernel-borderlands.wiki`)
* Synchronized the local wiki repository located at `/home/emergence/Desktop/kernel-borderlands.wiki/` with all design changes:
  * Overhauled `kb-checker.md` to document the Safety & Integrity Auditing layer rather than the obsolete Lua sandbox.
  * Updated `Architecture.md` to register `kb-mcp` and specify L1 Go caches as thread-safe `sync.Map` instances rather than lock-free caches.
  * Created the new `kb-mcp.md` wiki page detailing JSON-RPC stdio transport tools and resource paths.
  * Aligned links, paths, and maintainer roles in `Home.md`, `Team.md`, `_Sidebar.md.md`, `kb-tui.md`, `kb-dashboard.md`, and `Contributing.md`.

### E. Permanent Guidelines & Agent Memory
* Updated the permanent developer guidelines guide at [kernel-borderlands.md](../../.gemini/antigravity-cli/knowledge/kernel-borderlands.md):
  * Corrected IPC Unix Socket target paths to `/run/kb/kbd.sock`.
  * Appended **Section 9** detailing the Per-Process (TGID-based) rate-limiting token bucket and hybrid map configurations.
  * Appended **Section 10** confirming the complete absence of Lua interpreters or REPL features in Kernel Borderlands.
  * Appended **Section 11** detailing the operator interface thin-client architecture rules.
  * Appended **Section 12** documenting the architectural philosophy of the 4 operator surfaces.
* Updated [AGENT.md](../../AGENT.md) and [CLAUDE.md](../../CLAUDE.md) with these invariants.

### F. Community Engagement Template
* Created [docs/project/github_discussion_welcome.md](../project/github_discussion_welcome.md) to serve as a welcome template for the GitHub Discussions board. It outlines the core components, developer RFC contribution pathways, bi-weekly sync channels, and maintainer updates.

---

## 3. Impact Assessment
By restructuring the directories and centralizing specifications under `docs/specdocs/`, we have eliminated path ambiguities and clarified subsystem boundaries. Documenting the architectural philosophy of the four interfaces helps ensure future maintainers retain the separation of concerns between visual consoles, shell tools, remote terminal gateways, and AI-native protocol mediation layers.
