# Architecture

Technical documentation describing how Kernel Borderlands works internally.

| Document | Description |
|---|---|
| [`hookpoints.md`](./hookpoints.md) | Kernel hook points monitored by KB and the eBPF instrumentation strategy behind them. |
| [`cross-kernel-portability.md`](./cross-kernel-portability.md) | How KB achieves CO-RE/BTF-based portability across kernel versions without kernel-specific builds. |
| [`kbd-contracts.md`](./kbd-contracts.md) | The locked event contract (`event_type` values and metadata conventions) between kb-core and kb-control-plane. |
| [`kb-core_system_requirements.md`](./kb-core_system_requirements.md) | `kb-core`'s actual measured resource footprint (BPF map sizes, hook overhead) and a proposed Min/Recommended/Balanced/Max tier structure for future tunability — none of which exists yet; every deployment today gets the Max-tier footprint. |
| [`resource_management_roadmap.md`](./resource_management_roadmap.md) | Cross-subsystem (`kb-core` + `kb-control-plane` + `kb-checker`) path-to-production plan for turning the tier structure above into a real, safe-by-default product: runtime tunability, auto-detected tier selection, thermal-reactive throttling, SQLite retention, pre-flight validation, customer-facing hardware docs. Roadmap only — nothing implemented. |

These documents reflect the intended design. If source code and docs disagree, treat it as a bug — flag the discrepancy rather than assuming the code is the source of truth.
