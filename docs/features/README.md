# Feature Specifications (`docs/features/`)

This directory houses design specifications and improvement records for individual Kernel Borderlands features — see [`CLAUDE.md`](../../CLAUDE.md)'s Documentation Policy for how this fits into the docs precedence order.

---

## Document Catalog

- [`CPM.md`](CPM.md) — Critical Process Module: an authorization gate between the containment/enforcement pipeline and `contained_pids_map`/eBPF LSM hooks, deciding whether a given containment request would put the OS or the security platform itself at risk. Does not do detection/scoring — strictly gates enforcement.
- [`CWP.md`](CWP.md) — Critical Workload Protection: lets operators designate their own mission-critical applications as protected — fully monitored (behavioral analysis, telemetry, scoring) but excluded from automatic containment/termination, distinct from CPM's OS/KBS-infrastructure protection.
- [`gap-work.md`](gap-work.md) — Two small, signed-off implementation improvements to the containment restore path (checking `bpf_map_delete_elem()`'s return value; bounding a format specifier), plus the runtime validation procedure that confirms the restore path actually cleans up the kernel map.

Ray integration, AADS intelligence/JJE design, and gRPC-over-UDS development docs live in [`docs/development/control-aads/`](../development/control-aads/README.md), not here — see that directory's own catalog.
