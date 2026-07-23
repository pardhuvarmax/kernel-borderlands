# kb-core — System Requirements & Resource Footprint

**Component**: `kb-core` (Ring 0 eBPF sensor + userspace loader/bridge, `kbd_sensor`)
**Owner**: Pardhu (Lead Kernel Space Engineer, `kb-core` subsystem, per `docs/reports/kb-core/corev1-enhancements.md`)
**Status**: Documents the actual current, fixed footprint. The tier table below is a *target* structure for future tunability — **none of it exists yet**. As shipped today there is exactly one tier: whatever the compiled `#define`s produce, on every install, regardless of hardware.
**Written**: 2026-07-23, based on direct inspection of `kb-core/ebpf/kbd_sensor.bpf.c` and `kb-core/userspace/sensor/kbd_sensor.c` (map definitions, hook list, rate-limiter logic) — not estimated from documentation, measured from source.
**On the project's "zero-overhead" claim**: `kernel_borderlands_specification.md` §1 describes KB as a "zero-overhead threat detection... platform." This doc's footprint numbers below (§2-§3) don't contradict that — they're answering a different question. "Zero-overhead" in eBPF is the conventional claim about *per-hook latency on the traced operation itself* (a single `open()`/`mprotect()` call completes in near-negligible extra time versus older instrumentation like `ptrace`), which nothing here disputes and this doc never measured. What's documented below is *aggregate system-wide resource cost* from having many hooks continuously active — a separate property. A hook can be individually near-instant and the platform can still meaningfully load a CPU or grow memory/disk over time when it's this many hooks, this broadly scoped, running this continuously. Read the two claims as complementary, not conflicting.

---

## 1. What's Fixed Today (not configurable at runtime)

- **`KB_MAX_PROCESSES = 10240`** — a C `#define` in `kbd_sensor.bpf.c`, baked into the compiled `.bpf.o` at build time. No CLI flag, env var, or config file changes it. The only way to change it is editing the source and recompiling.
- **All hooks attach unconditionally.** `kbd_sensor_bpf__attach(skel)` attaches every LSM hook, kprobe, and uprobe as a single unit — there is no "reduced hook set" mode. Full list: `lsm/file_open`, `lsm/bprm_check_security`, `lsm/socket_bind`, `lsm/socket_connect`, `lsm/file_mprotect`, `kprobe/commit_creds`, `kprobe/security_capable`, plus TLS uprobes via `attach_ssl_uprobes()`.
- **Tier 1 events bypass rate limiting by design**, permanently: `commit_creds` (privilege escalation), LSM denials, TLS plaintext writes, `process_vm_writev`, `execve`. Per `docs/specifications/ebpf_rate_limiting_design_spec.md` this is an intentional security tradeoff (never silently drop a root-gain event under load) — but it means the busier/more-attacked a system is, the *less* throttling applies, not more.
- **kprobe/uprobe trap overhead is unavoidable regardless of rate limiting.** The token-bucket check happens *inside* the BPF program, after the kernel has already taken the trap into it. Rate-limiting reduces downstream ring-buffer/userspace processing; it does not reduce the per-call trap cost itself.

## 2. Measured Memory Footprint (as compiled today)

All figures from `kbd_sensor.bpf.c`'s actual map definitions, not estimates from docs.

| Map | Type | max_entries | Raw key+value | Notes |
|---|---|---|---|---|
| `kb_events` | `RINGBUF` | — | — | Flat 1MB, shared across all hooks. Always pinned. |
| `kb_syscall_counts` | `HASH` (no `BPF_F_NO_PREALLOC`) | `KB_MAX_PROCESSES * 64` = **655,360** | 16B (`u64` key + `u64` value) | **The dominant cost.** Standard `HASH` maps preallocate full capacity at load time. Real kernel per-entry overhead (`htab_elem` + bucket array) runs materially higher than the raw 16B — a reasonable estimate puts this map alone at **~40-50MB of pinned, non-swappable kernel memory**, reserved the instant `kbd_sensor` loads, independent of how many processes/syscalls actually exist. |
| `kb_syscall_totals` | `HASH` | 10,240 | 12B | Sub-MB. |
| `kb_cred_prev` | `HASH` | 10,240 | 24B | Sub-MB. |
| `kb_rate_limit_lru_map` | `LRU_HASH` | 10,240 | 48B | ~500KB raw; LRU maps evict under pressure so this doesn't grow unbounded the way the plain `HASH` maps do. |
| `contained_pids_map` | `HASH` | 1,024 | 8B | Negligible. |
| `kb_sensitive_paths` | `HASH` | 64 | ~68B | Negligible, <5KB. |
| `kb_ringbuf_drops` | `ARRAY` | 1 | 8B | Negligible. |

**Total estimated pinned kernel memory: ~40-50MB**, essentially all of it `kb_syscall_counts`. This is allocated at BPF-load time, not incrementally — a box with 5 running processes pays the same kernel-memory cost as a box that hits the full 10,240-process design ceiling.

Userspace (`kbd_sensor.c`) adds a fixed `delta_buf[KB_ENTROPY_MAX_MAP_ITER]` static array (`KB_ENTROPY_MAX_MAP_ITER = 50000`, 16 bytes/entry ≈ 800KB) — small relative to the kernel-side map, not a significant factor.

**Not covered above (separate subsystem — `kb-control-plane`, owner Teju, see its own catalog doc for the full write-up)**: `kbd`'s L1 `sync.Map` process-state cache grows with distinct tracked PIDs and currently has no eviction path for exited processes. Detailed here anyway, since disk footprint is part of "what hardware does this system need," which is this doc's actual subject regardless of which subsystem owns the fix.

### 2.5 SQLite retention/rotation gap (`kb-control-plane`, not `kb-core` — included here for the disk-sizing picture)

Schema, verified from `kb-control-plane/internal/store/schema.go`:

| Table | Growth pattern | Est. bytes/row | Notes |
|---|---|---|---|
| `process_state` | **Bounded** — `PRIMARY KEY(pid)`, upserted not appended | ~120B/row incl. 7 `dim_*` REAL columns | Stays roughly proportional to distinct live/recently-seen PIDs, not time. Not a long-run disk risk by itself. |
| `zone_transitions` | **Unbounded** — `id INTEGER PRIMARY KEY AUTOINCREMENT`, append-only | ~110-150B/row (`comm` TEXT + 2 indexes: `idx_zt_pid`, `idx_zt_ts`) | Grows every zone crossing, forever. No row ever deleted. |
| `audit_log` | **Unbounded** — `id INTEGER PRIMARY KEY AUTOINCREMENT`, append-only | ~280-350B/row (`prev_hash`/`entry_hash` are 64-char hex SHA-256 strings each) | Grows on every containment/policy/agent-decision action, forever. Deleting old rows isn't even safe without special handling — the hash chain (§1.5 of the `kb-control-plane` catalog) means removing a row breaks every subsequent hash unless rotation is chain-aware (e.g. archive-and-checkpoint with a new genesis hash, not a bare `DELETE`). |

**Why it matters for system requirements specifically**: the two append-only tables are the actual long-run disk-growth driver on any deployment. There is currently no retention policy, no archival job, no `VACUUM`/checkpoint schedule, and no config for "keep N days" — `kbd` will happily grow `state.db` indefinitely for as long as it runs. On a low-end box (the Min/Recommended tiers below, which tend to also have the smallest disks — SBCs, small VPS instances), this is the more pressing long-term constraint compared to the BPF memory footprint in §2, which is at least fixed and bounded; disk growth is not.

**What it would take to fix (`kb-control-plane` work, not `kb-core`)**: a time- or size-based rotation job that archives old `zone_transitions`/`audit_log` rows out of the live `state.db` (e.g. to a separate cold-storage file or export), designed so the hash chain in the archived segment remains independently verifiable and the live table starts a fresh, documented genesis hash rather than silently truncating history. Out of scope for this doc to design in full — flagged here so it's part of the hardware-sizing picture, with the real fix tracked on `kb-control-plane`'s side.

## 3. CPU / Thermal Footprint (qualitative — no per-hook benchmarks exist yet)

No profiling data exists in this repo quantifying per-hook CPU cost; the following is grounded in what the hooks *are*, not measurement:

- `security_capable` (kprobe) already filters aggressively in-kernel — early-returns for `uid == 0` and for all but 4 sensitive capabilities (`CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN`, `CAP_SYS_RAWIO`) before ever reserving a ring-buffer event. The trap itself still fires on every call system-wide; the *processing* it triggers is narrow.
- `commit_creds` (kprobe), TLS uprobes, and the four `lsm/*` hooks have no such filtering — they process every call that reaches them (subject to Tier 2 rate-limiting for the `lsm/*` hooks specifically; `commit_creds` and TLS uprobes are Tier 1, unthrottled).
- Uprobes are inherently more expensive per-hit than kprobes/tracepoints (breakpoint trap vs. a simpler instrumented callsite) — any process doing TLS handshakes pays this on every one.
- `scan_syscall_entropy()` runs every `KB_ENTROPY_SCAN_EVERY_N_POLLS` (10) non-empty polls of the ring buffer, and does real per-PID work: `/proc/<pid>/comm`, `/proc/<pid>/status`, `/proc/<pid>/stat` reads (`proc_backfill_identity()`) plus floating-point Shannon-entropy math, bounded by `KB_ENTROPY_MAX_MAP_ITER = 50000` iterations per scan.

**No tuning knob exists for any of the above.** No "lite mode," no selective hook disable, no way to turn off TLS uprobe attachment or widen the entropy-scan interval without recompiling.

---

## 4. Baseline Kernel Requirement (applies to every tier, not tier-dependent)

Verified against the actual host used in this session: `Linux 6.8.0-134-generic`, `CONFIG_BPF=y`, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, `bpf` present in the active `/sys/kernel/security/lsm` list, `/sys/kernel/btf/vmlinux` present. All four of these are non-negotiable regardless of which resource tier a deployment targets — there is no "Min tier" that relaxes the kernel requirement, only the workload-facing knobs in §2/§3.

- **Kernel ≥ 5.7** for `BPF_MAP_TYPE_RINGBUF` (used by `kb_events`); realistically **≥ 5.11+** is the safer floor for BPF LSM hook stability, matching the CO-RE/BTF portability approach described in `docs/architecture/cross-kernel-portability.md`.
- **`CONFIG_BPF_LSM=y`** and **`bpf` present in `/sys/kernel/security/lsm`** — without this, all five `lsm/*` hooks fail to attach; `kb-core` has no fallback detection/containment path if BPF LSM is unavailable.
- **`CONFIG_DEBUG_INFO_BTF=y`** (BTF for the running kernel, typically at `/sys/kernel/btf/vmlinux`) — required for CO-RE relocations; without it the compiled `.bpf.o` won't load on that kernel at all.
- **Root** (or equivalent `CAP_BPF`/`CAP_SYS_ADMIN` + `CAP_PERFMON` capabilities) to load and attach the BPF programs.

## 5. Full System Requirements — Min / Recommended / Balanced / Max

Combines `kb-core`'s BPF footprint (§2), the SQLite growth risk (§2.5, `kb-control-plane`), and the baseline kernel floor (§4) into one hardware-sizing picture for the whole stack (`kbd_sensor` + `kbd` + `kb-checker` together, since that's what actually needs to be sized for a real deployment). **As with §6 below, only the "as shipped" row reflects what runs today — the Min/Recommended/Balanced tiers require the tuning work in §6 to actually hit these numbers; right now every install pays the Max-tier cost.**

| Spec | **Min** | **Recommended** | **Balanced** | **Max** |
|---|---|---|---|---|
| **Target profile** | Small VPS, old SBC (e.g. Raspberry Pi 4-class), constrained container | Typical dev VM, budget cloud instance | Typical workstation or mid-size dedicated server | Security-dedicated host, high process/event churn |
| **CPU** | 1 vCPU | 2 vCPU | 4 vCPU | 8+ vCPU |
| **RAM (total system)** | 1GB | 2-4GB | 4-8GB | 8GB+ |
| **RAM — `kb-core` BPF maps** | Low single-digit MB (target, §6) | ~10-15MB (target, §6) | ~40-50MB (today's actual number) | ~50MB+, scales with process count if preallocation is dropped |
| **RAM — `kbd` (Go control plane)** | Tens of MB (small L1 cache, few tracked PIDs) | Low hundreds of MB | Several hundred MB, depends on distinct-PID churn (§2.5's L1 gap) | 1GB+ possible on very high-churn boxes given no L1 eviction yet |
| **Disk — initial** | <100MB (`state.db` schema + WAL overhead) | <100MB | <100MB | <100MB |
| **Disk — ongoing growth** | **No safe answer today** — §2.5's retention gap means this is unbounded on every tier alike. A rough planning number: at ~300B/audit-row and ~130B/zone-transition-row, every 100K combined events ≈ **~40MB**. Actual event rate is workload-dependent (idle dev box measured `events_per_second: 10.7`, §1.13-adjacent metrics — but zone transitions and audit entries are far rarer than raw events, so this doesn't translate directly to a per-day number without real production data). | Same growth mechanism, same lack of a cap | Same | Same, just reached faster given higher event volume |
| **Kernel** | §4 baseline, no exceptions | §4 baseline | §4 baseline | §4 baseline |
| **Network** | None required (`kba.sock`/`kbd.sock`/`kbc.sock` are all UDS, per `kb-control-plane`'s catalog §1.1/§5.3) — only SSH (`:2222`) is network-facing, and that's optional/operator-access only | Same | Same | Same |

**Bottom line on disk**: this is the one axis in the whole spec that genuinely has **no ceiling at any tier** until `kb-control-plane` builds the retention/rotation job described in §2.5. A Min-tier box with a small disk is the one most likely to actually run out of space first, purely because it started with less headroom — not because it does anything wrong.

---

## 6. Target Requirement Tiers — Engineering Detail (proposed structure — not yet implemented)

These tiers describe what *would* need to be true for `kb-core` to run well across a spread of hardware, expanding on the CPU/RAM columns from §5 with the actual compile-time knobs each tier would flip. **Today, every deployment gets the Max-tier footprint regardless of the box it's on** — there is no code path that produces the Min or Recommended numbers. Building that is the actual work item; this table is the target shape of it.

| Tier | `KB_MAX_PROCESSES` | `kb_syscall_counts` sizing | Hook set | TLS uprobes | Entropy scan |
|---|---|---|---|---|---|
| **Min** | ~512 | `BPF_F_NO_PREALLOC` + LRU instead of plain `HASH`, sized ~32K entries | Core only: `file_open`, `bprm_check_security`, `commit_creds` | Off | Disabled or very sparse (e.g. every 100 polls) |
| **Recommended** | ~2048 | `BPF_F_NO_PREALLOC`, ~128K entries | Core + network hooks (`socket_bind`/`connect`) | Off | Default interval, capped iteration count |
| **Balanced** | 10,240 (today's default) | As today, but `BPF_F_NO_PREALLOC` to avoid full preallocation | Full hook set | On | Default (`KB_ENTROPY_SCAN_EVERY_N_POLLS = 10`) — today's actual behavior |
| **Max** | 10,240+ (raise if needed) | As today | Full hook set | On | Frequent (e.g. every 5 polls), most aggressive |

**What it would take to make this real** (not scoped or started):
1. Turn `KB_MAX_PROCESSES` and the hook-attach set into runtime config (env vars read in `kbd_sensor.c`'s `main()`, alongside the existing `KBD_SOCKET_PATH` pattern) instead of compile-time constants.
2. Add `BPF_F_NO_PREALLOC` to `kb_syscall_counts` (and ideally move it to `LRU_HASH` like `kb_rate_limit_lru_map` already is) so kernel memory scales with actual usage instead of the theoretical maximum — this alone would eliminate most of the ~40-50MB fixed cost regardless of which tier a box targets.
3. Make `attach_ssl_uprobes()` conditional on a flag, since TLS uprobe attachment is one of the more expensive per-hit hooks and isn't relevant to every deployment (e.g. a box with no TLS-terminating workloads).
4. Make `KB_ENTROPY_SCAN_EVERY_N_POLLS` and `KB_ENTROPY_MAX_MAP_ITER` runtime-tunable, since the entropy scan's `/proc` reads are real, avoidable-when-unneeded cost.
5. Decide what "Min tier" actually drops — e.g. is entropy scoring (`dim_score[KB_DIM_SYSCALL]`) acceptable to lose on a constrained box, or does it need a cheaper approximation instead of just "scan less often"? This is a product/security decision, not just an engineering one, and belongs to whoever owns detection-quality tradeoffs, not just `kb-core`.

**For the full path from this list to a shipped product** — auto-detected tier selection, thermal-reactive throttling, SQLite retention, pre-flight validation, customer-facing hardware docs — see the standalone cross-subsystem roadmap: [`resource_management_roadmap.md`](./resource_management_roadmap.md). That doc spans `kb-core`, `kb-control-plane`, and `kb-checker` together, which is why it's kept separate from this `kb-core`-scoped requirements doc rather than appended here.

### Does this tier table actually make old/constrained hardware safe? A graduated answer, not a blanket yes.

Worth stating plainly here, not just in the roadmap doc: shipping §6's tunability closes most of the resource gap, but not all of it — two costs are structurally independent of `kb-core`'s own tuning knobs, so "Min tier exists" doesn't uniformly mean "now safe" across every machine that would want it.

| Hardware class | Verdict once §6 ships | Why |
|---|---|---|
| **Mainstream/medium hardware** (meets §4's kernel floor, modest but real RAM/disk margin) | **Yes — genuinely safe zone.** | Min tier's `BPF_F_NO_PREALLOC`+`LRU_HASH` conversion drops the fixed memory cost from ~40-50MB to low single-digit MB; the reduced "core only" hook set (no TLS uprobes, no `security_capable`, no network/`mprotect` hooks) removes the most expensive per-hit hook categories and most of the aggregate Tier-1 event surface along with them. This resolves nearly all of what §2/§3 above identified as the cost driver for this class. |
| **Older but kernel-compatible** (meets §4's floor, but limited RAM/disk) | **Mostly — much improved, not unconditionally safe until `kb-control-plane`'s retention work also ships.** | Same CPU/RAM relief applies. But `zone_transitions`/`audit_log` (§2.5) still grow unbounded at *any* `kb-core` tier — that fix is entirely outside this doc's scope (Teju, `kb-control-plane`, tracked as Phase 4 in the roadmap). A machine with a small/slow disk is exactly the one most exposed to this, and nothing in §6 touches it. |
| **Kernel-incompatible** (predates solid `CONFIG_BPF_LSM=y`/`CONFIG_DEBUG_INFO_BTF=y` support) | **No — unaffected by §6 entirely.** | §4's kernel/BTF requirement is a hard floor, not a resource knob. Even Min tier still needs BPF LSM hooks and CO-RE relocations to function at all — tunability changes *how much* runs, not *whether the kernel can run it in the first place*. Only fix: update the kernel, an operator action outside this doc's scope. |

Full reasoning and the intended-deployment-model context behind this table: [`resource_management_roadmap.md`](./resource_management_roadmap.md#would-phase-12-tunability-actually-make-mediumold-laptops-safe-a-graduated-answer-not-a-blanket-yes).

---

## Changelog

- **2026-07-23**: Initial doc. Established the current fixed footprint (measured from source, not estimated) and proposed the four-tier target structure. No implementation work done — this is a requirements/planning document only.
- **2026-07-23**: Added §2.5 (SQLite retention/rotation gap, `kb-control-plane` scope, included here for disk-sizing purposes) and §4/§5 (baseline kernel requirement + full Min/Recommended/Balanced/Max hardware spec table covering the whole stack, not just `kb-core`'s BPF footprint). Renumbered the original tier table to §6.
- **2026-07-23**: Added the "zero-overhead claim" clarification note (per-hook latency vs. aggregate footprint — the two aren't in conflict), and a graduated hardware-class verdict table (mainstream: safe once §6 ships / older-but-kernel-compatible: mostly, pending `kb-control-plane`'s retention work / kernel-incompatible: unaffected by tunability entirely) after §6, mirrored from `resource_management_roadmap.md`.
