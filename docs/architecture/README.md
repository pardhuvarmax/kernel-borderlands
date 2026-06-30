# Architecture

Technical documentation describing how Kernel Borderlands works internally.

| Document | Description |
|---|---|
| [`hookpoints.md`](./hookpoints.md) | Kernel hook points monitored by KB and the eBPF instrumentation strategy behind them. |
| [`cross-kernel-portability.md`](./cross-kernel-portability.md) | How KB achieves CO-RE/BTF-based portability across kernel versions without kernel-specific builds. |
| [`kbd-contracts.md`](./kbd-contracts.md) | The locked event contract (`event_type` values and metadata conventions) between kb-core and kb-control-plane. |

These documents reflect the intended design. If source code and docs disagree, treat it as a bug — flag the discrepancy rather than assuming the code is the source of truth.
