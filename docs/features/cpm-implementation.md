# Implement CPM (Critical Process Module) in kb-core

## Context

`docs/features/CPM.md` is a design spec (Status: Design Specification) for an authorization
gate that sits between containment recommendations and actual enforcement
(`contained_pids_map` + eBPF LSM hooks), rejecting containment requests against PID 1,
kernel threads, the sensor's own components, and admin-designated protected executables.
It's the highest-priority item in `docs/features/` — `gap-work.md` (the other kb-core
feature-doc item) is already done, and CWP explicitly depends on CPM running first in the
pipeline (CWP.md §8).

Grep confirms nothing from the spec exists in code yet (no `protected_pids_map`,
`protected_workloads_map`, `CPM_`/`CWP_` anywhere in `kb-core` or `kb-control-plane`).

**One deliberate deviation from the spec's literal text, worth stating up front:** CPM.md's
`cpm_classify()` (§5.4) is written as an in-kernel function operating on `struct task_struct
*task`. But tracing the actual codebase shows containment is *not* decided synchronously
in-kernel — `kb-control-plane` (Go) decides containment and pushes a `kb_wire_containment_cmd`
over the UDS bridge; `kbd_sensor.c`'s `handle_incoming_containment_cmd()`
(`userspace/sensor/kbd_sensor.c:563`) is the actual, sole place that calls
`bpf_map_update_elem()`/`bpf_map_delete_elem()` on `contained_pids_map`. That function is the
real "last gate before enforcement" (spec §4.2) in this codebase — so CPM's classifier will
live there in userspace C, not as in-kernel eBPF C. The BPF-side building blocks the spec
calls for (`protected_pids_map`, structural kernel-thread detection, the `exec()`
registration hook) are implemented in eBPF exactly as specified; only the final decision
function's location differs from the spec's diagram, to match where the choke point actually
is. This will be called out again in the commit/handoff so it doesn't read as silently
deviating from the doc.

## Scope for this pass

Fully implements CPM's runtime behavior (all of §11's acceptance criteria) using kb-core's
existing patterns. One piece is a stub-only, flagged as follow-up: the operator/admin
protected-executable registry is normally pushed live from Go (`kbctl protect --path ...`,
spec §7.4) the same way `kb_sensitive_paths` is today (compiled-in floor + wire-pushed
overlay, see `apply_sensitive_paths_frame()`). This pass adds the C-side receiver for that
push (new wire msg type, mirroring `KB_WIRE_MSG_SENSITIVE_PATHS`) but does **not** implement
the Go-side sender — that's a `kb-control-plane` change, out of kb-core's scope, and will be
noted as open follow-up work rather than silently done or silently skipped.

## Implementation

### 1. `kb-core/ebpf/kbd_sensor.bpf.c` — BPF maps + registration/deregistration hooks

- Add `protected_pids_map`: `BPF_MAP_TYPE_HASH<u32 pid, u8>`, `max_entries=2048` (per spec
  §5.1, sentinel value only).
- Add `protected_exec_paths_map`: `BPF_MAP_TYPE_HASH<char[64], u8>`, `max_entries=64` —
  mirrors the existing `kb_sensitive_paths` map exactly (same key size/shape), holding the
  compiled-in-floor + operator-pushed protected executable paths.
- Extend `kb_handle_exec` (`tp/sched/sched_process_exec`, line 237): read the tracepoint's
  `__data_loc_filename` field (`struct trace_event_raw_sched_process_exec`, confirmed present
  in `include/vmlinux.h:93218`) into a 64-byte buffer, look it up in
  `protected_exec_paths_map`; on match, `bpf_map_update_elem(&protected_pids_map, &pid, ...)`.
  This is the exec-time registration path from spec §5.3/§7.2. (Matching is on the raw
  execve path, same limitation the existing `is_sensitive_path()` has — not a new gap.)
- Extend `kb_handle_exit` (`tp/sched/sched_process_exit`, line 248):
  `bpf_map_delete_elem(&protected_pids_map, &pid)` unconditionally — cheap no-op if absent,
  implements spec §7.3 (PID-reuse safety).

### 2. `kb-core/userspace/sensor/kbd_sensor.c` — classifier, registry loading, startup scan

- **`is_kernel_thread(pid_t pid)`**: userspace has no `task_struct` pointer, so the
  structural `task->mm == NULL` check (spec §3.2/§5.4) is done via
  `readlink("/proc/<pid>/exe", ...)` — kernel threads have no `exe` link and the syscall
  fails with `ENOENT`/`EINVAL`, which is the standard userspace-visible signal for "no mm".
- **`cpm_classify(pid_t pid)`** returning the exact `enum cpm_decision` from spec §5.4
  (`CPM_ALLOW`, `CPM_REJECT_KERNEL_THREAD`, `CPM_REJECT_PID1`, `CPM_REJECT_PROTECTED_PID`,
  `CPM_REJECT_PROTECTED_EXEC`), checks ordered cheapest-first exactly as spec'd: PID==1 →
  kernel-thread → `protected_pids_map` lookup → protected-exec-path re-check (race-safety
  net per spec §5.5, using the same `protected_exec_paths_map`).
- **`populate_protected_exec_paths(skel)`**: compiled-in floor, mirrors
  `populate_sensitive_paths()` (line 880) exactly in structure. Floor list: `systemd`,
  `systemd-logind`, `systemd-udevd`, `dbus-daemon`, `NetworkManager` at their standard
  distro paths (spec §3.1 examples) — sibling-subsystem binaries (`kbd`, `kb-checker`,
  `kbctl`) are **not** guessed into this list since their install paths aren't documented
  anywhere in this repo; that's a real gap, called out in the handoff, not papered over.
- **CPM self-protection at startup**: register the sensor's own PID (`getpid()`) into
  `protected_pids_map` directly, before the bridge connects or any containment command can
  arrive — satisfies spec §3.3/§7.1 item 2 for `kbd_sensor` itself without depending on the
  exec-path registry (this process already execed before the hook could catch it).
- **Startup `/proc` reconciliation scan** (spec §7.1 item 3): iterate `/proc/<pid>/exe`,
  compare canonical resolved path against the floor registry, pre-register matches into
  `protected_pids_map`. New code — no existing `/proc`-scanning helper in this codebase to
  reuse (confirmed via grep).
- **Wire receiver stub** for operator-pushed protected paths: add
  `KB_WIRE_MSG_CPM_PROTECTED_EXEC = 7` to `kb_bridge.h` (7 is the next free value — 3 is
  already double-booked, 6 is `SENSITIVE_PATHS`, per the existing comment block) and
  `apply_cpm_protected_exec_frame()` / `read_cpm_protected_exec_from_bridge()`, structurally
  identical to `apply_sensitive_paths_frame()`/`read_sensitive_paths_from_bridge()`. Wired
  into the same bridge read loop alongside the sensitive-paths read. No Go-side sender —
  frames simply never arrive until `kb-control-plane` adds one (follow-up work, noted below).
- **Gate `handle_incoming_containment_cmd()`** (line 563): immediately before the `level !=
  0` branch's `bpf_map_update_elem()` (the actual enforcement write), call
  `cpm_classify(pid)`. On any `CPM_REJECT_*`, skip the map write entirely and emit the audit
  log instead. The `level == 0` (release) branch is untouched — releasing containment is
  always allowed, CPM only gates the addition of new containment.
- **Audit logging** (spec §9): on rejection, print a structured line matching the existing
  `[SENSOR]` log style used two lines below it (`printf("[CPM] Containment Prevented ...")`),
  including PID, resolved comm/exec path, and rejection reason — covers spec §9.1's fields
  except `requesting_component` (not available at this layer; the wire cmd doesn't carry it,
  and adding it would touch the locked `kb_wire_containment_cmd` struct and the Go sender,
  out of scope here). Full pipeline-forwarding into telemetry (§9.4, a new locked
  `event_type` value) is also flagged as follow-up rather than done — `docs/architecture/
  kbd-contracts.md`'s event_type list is explicitly locked and shared with `kb-control-plane`
  Go dispatch code; adding one is a cross-subsystem change this pass doesn't make.

### 3. Build

No `Makefile` changes needed — `kbd_sensor` is already a build target compiling
`ebpf/kbd_sensor.bpf.c` + `userspace/sensor/kbd_sensor.c` + the bridge sources together.

## Verification

1. `cd kb-core && make clean && make` — confirms the eBPF verifier accepts the new map
   lookups/updates in `kb_handle_exec`/`kb_handle_exit`, and the userspace side compiles
   clean.
2. Runtime check using the existing mock-control-plane test harness
   (`tests/test_restore_ipc.py`, already sends `kb_wire_containment_cmd` frames over a fake
   `kbd.sock`): run `sudo ./build/kbd_sensor`, then drive the mock harness (or a small ad hoc
   variant of it) to send a containment command for PID 1 and for `kbd_sensor`'s own PID —
   confirm both are rejected with `[CPM] Containment Prevented` log lines and **no** entry
   appears in `contained_pids_map` (`sudo bpftool map dump name contained_pids_map`).
3. Send a containment command for an ordinary unprotected PID (e.g. a `sleep 100 &`
   background process) — confirm it's still accepted and enforced as before (regression
   check that CPM doesn't over-block).
4. `tests/test_all_hooks.sh` — general regression pass to confirm the exec/exit hook
   additions haven't broken existing telemetry on those two tracepoints.

## Explicit follow-up (not done this pass, to hand off cleanly)

- `kb-control-plane` (Go) sender for `KB_WIRE_MSG_CPM_PROTECTED_EXEC` + a `kbctl protect
  --path` admin command (spec §7.4) — cross-subsystem, Go-side work.
- Sibling-subsystem binary paths (`kbd`, `kb-checker`, `kbctl`) in the compiled-in floor —
  needs their actual install paths, undocumented in this repo today.
- `requesting_component` audit field and full telemetry-pipeline forwarding of CPM rejection
  events — needs a new locked `event_type` and Go-side dispatch handling.
