# Kernel Borderlands Work Reports (`docs/reports/`)

This directory houses the chronological session and daily development cycle progress reports compiled by the Kernel Borderlands platform engineering leads.

---

## 📂 Reports Catalog

### 1. [Containment RL Training — August 2, 2026](kb-aads/containment-rl-2026-08-02.md)
* **Engineers**: Karthik (AI & Agentic Systems), PardhuVarma (ML & Systems)
* **Subsystems**: AADS Swarm (`kb-aads`), dataset tooling, Colab CLI training workflow.
* **Achievements**: Built a real ADFA-LD-based dataset pipeline (syscall traces, not network flow — matches what KB actually hunts), fixed the `ContainmentEnv` stub, trained an RLlib PPO policy via the `colab` CLI (fixing a real upstream `jupyter_kernel_client` bug along the way), root-caused and fixed an `event_type` feature-collision bug between training runs, wired the resulting checkpoint into live inference, and verified it end-to-end against the real running `kb-core`/`kb-control-plane` pipeline.

### 2. [Work Report — July 8, 2026](kb-core/july_08_2026.md)
* **Lead Engineer**: K. Pardhu (Systems & Security Lead)
* **Subsystems**: Safety Watchdog (`kb-checker`), Core Telemetry (`kb-core`), AADS Swarm (`kb-aads`), Control Plane (`kb-control-plane`), Systemd Gating, & Collaborative Roadmaps.
* **Achievements**: Implemented dynamic eBPF instruction hashing, BPF map self-healing audits, hook performance latency checks, active liveness heartbeats, mock integration tests, single-instance PID locking, 3-layer watchdog hard fallback containment (SIGKILL, bpftool, iptables), Go control plane UDS specs, 7 threat simulation event sets, and comprehensive readme overhauls.

### 3. [Work Report — July 7, 2026](kb-core/work_report_2026_07_07.md)
* **Lead Engineer**: K. Pardhu (Systems & Security Lead)
* **Subsystems**: Operator Interfaces, GitHub Wiki, Developer Guidelines, & Website.
* **Achievements**: Refactored operator clients under `kb-op/`, consolidated specification documents in `docs/specdocs/`, synchronized the off-tree GitHub wiki repository, updated the platform website index page, and established permanent developer rules and constraints.

### 4. [June 26 Status Report](kb-control-plane/june26-26.md)
* **Subsystem**: Control Plane (`kb-control-plane`).
* **Note**: not previously listed in this catalog — added for completeness.
