# Critical Workload Protection (CWP)

**Version:** 2.0
**Component:** Kernel Behaviour Sensor (KBS)
**Status:** Design Specification (Expanded)

---

# 1. Overview

**Critical Workload Protection (CWP)** is a policy subsystem that allows organizations to designate their own mission-critical applications as protected workloads. These workloads continue to be fully monitored by the Kernel Behaviour Sensor (KBS) — behavioral analysis, telemetry collection, forensic event generation, and threat scoring all continue unchanged — but are excluded from automatic containment and termination.

Unlike **Critical Process Module (CPM)**, which protects operating system infrastructure and KBS's own components, CWP protects applications that are essential to an organization's business operations. These are not inherently critical to Linux itself, but interrupting them can cause outages, financial loss, or data unavailability.

This document expands the original CWP specification with full architectural detail: component interactions, registration lifecycle, executable identity strategy, BPF/userspace data structures, the full decision pipeline, alert escalation, false-positive mitigation, security hardening against evasion, configuration formats, edge-case handling, and performance considerations.

---

# 2. Detailed Architecture with Component Interactions

## 2.1 Component Map

```text
┌───────────────────────┐
│   Policy Source        │   (YAML/TOML file, config API, cluster sync)
│  (admin-authored)      │
└───────────┬───────────┘
            │ load / reload
            ▼
┌───────────────────────┐        ┌──────────────────────────┐
│ Policy Loader (uspace) │──────▶│ Protected Workload        │
│  - parse & validate    │       │ Registry (uspace, in-mem) │
│  - resolve identities   │       │  - path/hash/inode table  │
└───────────┬───────────┘        └────────────┬─────────────┘
            │                                    │
            │ push resolved identities           │ lookup on exec
            ▼                                    ▼
┌───────────────────────┐        ┌──────────────────────────┐
│ exec() BPF Hook         │──────▶│ protected_workloads_map    │
│ (kernel, per-process)  │       │  (BPF hash map: PID→flags)│
└───────────┬───────────┘        └────────────┬─────────────┘
            │                                    │
            │ exit()                             │ lookup on containment
            ▼                                    ▼
┌───────────────────────┐        ┌──────────────────────────┐
│ exit() BPF Hook         │       │ Containment Decision       │
│  - deregister PID       │       │ Pipeline: Detection→CWP   │
└───────────────────────┘        │ →CPM→LSM                  │
                                   └────────────┬─────────────┘
                                                │
                                                ▼
                                   ┌──────────────────────────┐
                                   │ Alerting / Audit Pipeline  │
                                   └──────────────────────────┘
```

## 2.2 Component Responsibilities

| Component | Responsibility |
|---|---|
| Policy Loader | Reads and validates administrator policy, resolves executable identities, publishes an immutable snapshot to the registry |
| Protected Workload Registry (userspace) | Holds the canonical, human-editable list of protected identities (paths, hashes, inodes) and their metadata (owner team, justification, added-by) |
| `protected_workloads_map` (BPF) | Kernel-resident fast-lookup table of currently running protected PIDs |
| exec() Hook | Fires on every `execve()`; resolves the new process's identity and checks it against the registry; inserts into the BPF map on match |
| exit() Hook | Fires on process exit; removes the PID from `protected_workloads_map` to prevent PID-reuse issues |
| Containment Decision Pipeline | Orchestrates Detection → CWP → CPM → LSM evaluation order for every containment recommendation |
| Alerting/Audit Pipeline | Emits elevated alerts and structured audit events whenever a protected workload is flagged or a containment request is rejected |

## 2.3 Why CWP Sits Where It Does in the Pipeline

CWP is evaluated **after CPM** in the decision pipeline (see §7), not before it and not merged with it. This ordering matters:

* CPM protects the substrate the whole platform runs on (kernel, sensor, PID 1). Those checks are cheap, structural, and non-configurable — they should always run first and cannot be disabled by policy.
* CWP protects business applications via administrator-configurable policy. Because it's configurable, it must never be allowed to accidentally *shadow or weaken* CPM's guarantees — keeping it as a strictly later, independent stage prevents a workload policy from ever being able to, say, unprotect the sensor.

---

# 3. Workload Registration Lifecycle

## 3.1 Lifecycle States

```text
┌────────────┐   policy load    ┌───────────────┐   exec() match   ┌───────────────┐
│ Unregistered│ ───────────────▶│  Policy-Known  │─────────────────▶│ Actively       │
│ (not in any │                  │ (in registry,  │                  │ Protected      │
│  policy)    │                  │ no running PID)│                  │ (PID in BPF map)│
└────────────┘                  └───────────────┘                  └───────┬───────┘
                                                                            │ exit()
                                                                            ▼
                                                                    ┌───────────────┐
                                                                    │ Policy-Known   │
                                                                    │ (PID removed)  │
                                                                    └───────────────┘
```

## 3.2 State Transition Detail

1. **Unregistered → Policy-Known**: An administrator adds an executable identity to policy. The Policy Loader validates and resolves it (see §5) and stores it in the userspace registry. No BPF map entry exists yet — nothing is running.
2. **Policy-Known → Actively Protected**: A process executes an image matching a policy-known identity. The exec() hook inserts the PID into `protected_workloads_map`.
3. **Actively Protected → Policy-Known**: The process exits. The exit() hook removes its PID from the BPF map. The identity remains policy-known for the next time it starts.
4. **Policy-Known → Unregistered**: An administrator removes the identity from policy. Any currently running PIDs remain protected until they next exit (see §12.2 for the alternative "immediate revocation" mode), after which no new instances register as protected.

## 3.3 Startup Reconciliation

At KBS startup (and after any policy reload), CWP performs a **reconciliation scan**:

```text
Policy Loaded
      │
      ▼
Enumerate /proc for running processes
      │
      ▼
For each process: resolve identity → matches policy?
      │
   ┌──┴──┐
  YES    NO
   │      │
   ▼      ▼
Insert   Skip
into map
```

This ensures workloads already running before KBS starts (or before a policy update) are protected immediately, rather than only on their *next* restart.

---

# 4. Policy Loading and Synchronization

## 4.1 Load Path

```text
Policy File (YAML/TOML)
      │
      ▼
Schema Validation
      │
      ▼
Identity Resolution (path → inode/hash, see §5)
      │
      ▼
Build Immutable Snapshot
      │
      ▼
Atomic Pointer Swap into Active Registry
      │
      ▼
Startup Reconciliation Scan (§3.3)
```

* Policy is parsed into an **immutable snapshot** structure. Reloads never mutate the structure in place — a new snapshot is built fully, validated, and only then atomically swapped in. This guarantees that any in-flight classification always sees a fully consistent registry, never a partially-loaded one.
* Invalid policy (bad YAML, unresolvable paths, conflicting entries) fails the load and **retains the previous known-good snapshot** — CWP never runs with a partially-applied or broken policy.

## 4.2 Reload Triggers

* File-watch on the local policy file (inotify) for single-host changes.
* Explicit `kbctl policy reload` for administrator-driven changes.
* Cluster-wide policy synchronization (§4.3) for fleet-managed changes.

## 4.3 Cluster-Wide Synchronization

For fleets managed centrally:

```text
Central Policy Store
      │  (push or pull, e.g. every N minutes / on change)
      ▼
Per-Host Policy Cache (local file, signed)
      │
      ▼
Local Policy Loader (§4.1)
```

* The central store is the source of truth; each host caches the last-known-good signed policy locally so that CWP protection continues to function correctly even if the host loses connectivity to the central store.
* Policy documents are signed; hosts reject unsigned or signature-mismatched policy updates and continue running the last valid signed snapshot.

---

# 5. Executable Identity: Path vs Inode vs Hash

Choosing how to identify a "protected workload" is a core security decision, since the identity mechanism is exactly what an attacker would try to spoof or evade.

## 5.1 Comparison

| Identity Method | Pros | Cons | Recommended Use |
|---|---|---|---|
| **Path** (`/usr/bin/postgres`) | Human-readable, simple to author, matches how admins think about services | Vulnerable to path-based tricks: a malicious binary placed at the same path, or the legitimate binary moved/symlinked | Baseline identity for well-managed, immutable-infra deployments |
| **Inode** (device + inode number) | Cheap kernel-side comparison, immune to path renaming tricks | Breaks on every binary upgrade/redeploy (new inode); not portable across hosts | Supplementary check for high-assurance environments with controlled deployment pipelines |
| **Content Hash** (e.g., SHA-256 of the binary) | Strongest guarantee — verifies *what* is running, not just *where* | Most expensive to compute; requires re-hash on every legitimate upgrade; must be resolved at exec time or cached | High-assurance / security-infrastructure workloads (Vault, auth services) |

## 5.2 Recommended Layered Approach

CWP resolves identity using a **layered model** rather than a single method:

```text
exec() event
      │
      ▼
Resolve canonical path (post-symlink resolution)
      │
      ▼
Path matches a policy entry?
      │
   ┌──┴──┐
  NO     YES
   │      │
   ▼      ▼
 No match  Does policy entry require hash verification?
             │
          ┌──┴──┐
         NO      YES
          │        │
          ▼        ▼
      Register   Compute/lookup cached hash of binary
      as         → matches expected hash?
      protected      │
                   ┌──┴──┐
                  YES    NO
                   │       │
                   ▼       ▼
               Register   Reject match, log
               as         security event
               protected
```

* **Default tier (path-based):** sufficient for most workloads where the deployment pipeline already controls what lands at a given path (containerized, image-based deployments).
* **Elevated tier (path + hash):** required for policy entries marked `verify: hash` in configuration (see §11) — typically security infrastructure and anything internet-facing.
* Inode is used internally as a fast-path cache key (to avoid re-resolving/re-hashing a binary that hasn't changed since the last check), not as a standalone trust boundary.

---

# 6. BPF Map Design and Userspace Data Structures

## 6.1 BPF Map: `protected_workloads_map`

```c
struct workload_flags {
    __u8  protected;        // 1 = protected
    __u8  identity_tier;    // 0 = path, 1 = path+hash
    __u32 policy_id;        // reference into userspace policy table
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);                 // PID
    __type(value, struct workload_flags);
    __uint(max_entries, 8192);
} protected_workloads_map SEC(".maps");
```

* Sized larger than CPM's `protected_pids_map` (8192 vs 2048) since organization-defined workloads can be numerous in large deployments (many microservice instances).
* `policy_id` allows the alerting pipeline to look up rich metadata (owner team, justification, config source) from the userspace registry without embedding large structures in kernel memory.

## 6.2 Userspace Registry Structure

```c
struct workload_policy_entry {
    char     canonical_path[PATH_MAX];
    uint8_t  expected_hash[32];      // SHA-256, zero if hash tier not used
    uint8_t  identity_tier;          // 0 = path, 1 = path+hash
    uint32_t policy_id;
    char     owner_team[64];
    char     justification[128];
    time_t   added_at;
};
```

* Held as an in-memory hash map keyed by canonical path for O(1) lookup during exec-time resolution.
* Immutable snapshot pattern (§4.1): reload builds a new table and atomically swaps a pointer, so readers never observe a half-updated table.

---

# 7. Runtime Registration Workflow

```text
execve() syscall
      │
      ▼
exec() BPF hook fires
      │
      ▼
Resolve canonical executable path
(resolve symlinks, containerized root if applicable)
      │
      ▼
Lookup in userspace registry snapshot
      │
   ┌──┴──┐
  Miss   Hit
   │      │
   ▼      ▼
No       Identity tier == hash?
action        │
           ┌──┴──┐
          NO     YES
           │       │
           ▼       ▼
       Insert   Hash binary (or use cached
       PID      hash if inode unchanged)
       into           │
       BPF map    Matches expected_hash?
                     │
                  ┌──┴──┐
                 YES    NO
                  │       │
                  ▼       ▼
              Insert   Log security event
              PID      ("spoofed workload
              into      identity attempt"),
              BPF map   do NOT register
```

This runs once per `exec()` and is designed to stay on the fast path for the common (path-tier) case; hash computation is only triggered for entries explicitly requiring the elevated tier.

---

# 8. Detection → CWP → CPM → LSM Decision Pipeline

## 8.1 Pipeline Order

Note: the original document listed "CPM Check" before "CWP Check." This expanded design **fixes CPM's position as the first, non-configurable gate**, with CWP evaluated second, for the reasons given in §2.3.

```text
Detection Engine
      │  (risk score generated, containment recommended)
      ▼
┌─────────────────┐
│   CPM Check       │   ← structural / built-in, cannot be overridden by policy
└────────┬─────────┘
         │ not rejected by CPM
         ▼
┌─────────────────┐
│   CWP Check       │   ← administrator-policy-driven
└────────┬─────────┘
         │ not rejected by CWP
         ▼
┌─────────────────┐
│ contained_pids_map│
└────────┬─────────┘
         ▼
┌─────────────────┐
│  eBPF LSM         │
│  Enforcement      │
└─────────────────┘
```

## 8.2 Rationale for This Ordering

* CPM answers "would this destabilize the OS or the sensor itself?" — an answer that must never depend on administrator configuration.
* CWP answers "did the organization explicitly decide this application should not be auto-contained?" — a business decision layered on top of a stable substrate.
* Evaluating CPM first guarantees that even a misconfigured or overly broad CWP policy (e.g., an admin accidentally protecting `/usr/bin/*`) can never be used to defeat CPM's kernel/sensor protections, because CWP is never consulted for a request CPM has already rejected.

## 8.3 Combined Decision Table

| CPM Result | CWP Result | Final Outcome |
|---|---|---|
| Reject | (not evaluated) | Containment rejected — CPM reason logged |
| Allow | Reject | Containment rejected — CWP reason logged, elevated alert |
| Allow | Allow | Containment proceeds to `contained_pids_map` / LSM |

---

# 9. Alert Escalation Flow

## 9.1 Flow

```text
Detection Event on Protected Workload
      │
      ▼
Risk Score Computed
      │
      ▼
CWP Match Confirmed
      │
      ▼
Severity Escalation
  (protected-workload alerts are escalated
   one tier above their raw risk score)
      │
      ▼
Alert Routed to:
  - SIEM / SOAR integration
  - On-call paging (if severity ≥ threshold)
  - Dashboard "Protected Workload Alerts" view
      │
      ▼
Structured Audit Event Recorded
```

## 9.2 Why Escalate Severity

A high-risk detection on a protected workload is *more* operationally significant than the same detection on an ordinary process — the platform's automatic safety net (containment) is not going to act, so a human is the only remaining control. CWP therefore escalates alert severity by one tier (e.g., Medium → High, High → Critical) whenever the alerting process is confirmed to be a protected workload, rather than presenting it at its raw score.

## 9.3 Example Alert

```text
[CWP] Protected Workload Alert — ESCALATED
Process: postgres
PID: 2148
Executable: /usr/bin/postgres
Identity Tier: path
Raw Risk Score: 82 (High)
Escalated Severity: Critical
Containment: Prevented
Reason: Administrator Protected Workload (policy_id=17, owner=data-platform-team)
Recommended Action: Manual investigation required
```

---

# 10. False Positive Mitigation Strategy

Because protected workloads are, by definition, *not* automatically contained, false positives on them carry more residual risk than on ordinary processes (there's no automatic backstop). CWP mitigates this in several ways:

1. **Escalated alerting, not silence** (§9) — a false positive still surfaces prominently to a human, rather than being auto-remediated *or* quietly logged at normal severity.
2. **Justification metadata** — every policy entry requires an `owner_team` and `justification` field (§6.2, §11), so alerts can be routed to the team that understands the workload's expected behavior, reducing investigation time and false-alarm fatigue.
3. **Tunable per-workload risk thresholds** (see §14 Future Enhancements in the original spec, retained here) — allow a workload with known noisy-but-benign behavior (e.g., a database doing legitimate bulk I/O) to have a higher alerting threshold without lowering its protection from containment.
4. **Forensic snapshotting on high-severity detections** — even without containment, a high-confidence detection on a protected workload can trigger an automatic forensic snapshot (memory/process state capture) so investigators have evidence even though the process kept running.
5. **Periodic policy review reminders** — `added_at` and `owner_team` metadata support periodic audit reports ("workloads protected > 12 months without review") to catch stale or overly broad protections before they mask a real incident.

---

# 11. Security Considerations

## 11.1 Attacker Renaming or Replacing Binaries

**Threat:** An attacker drops a malicious binary at a protected path (e.g., overwrites or replaces `/usr/bin/postgres`) hoping to inherit CWP's containment exemption.

**Mitigations:**
* Path-tier protection alone is acknowledged as vulnerable to this (§5.1) — it is the *default*, not the *only*, tier.
* Security-sensitive entries should be configured with `verify: hash` (§5.2, §11.3), which detects any binary content change at the protected path and refuses to register it as protected — instead logging a distinct "spoofed workload identity attempt" security event (§7).
* File-integrity monitoring (already part of KBS's broader telemetry) independently flags unexpected writes to protected paths, providing a second, orthogonal detection signal even before the process executes.

## 11.2 Attacker Renaming a Malicious Process to Match an Unprotected-but-Similar Name

**Threat:** Process *name* spoofing (e.g., `comm` field set to `postgres`) without matching the actual executable path.

**Mitigation:** CWP matches on **resolved executable path** (and optionally hash), never on the `comm`/process-name field alone, which is trivially attacker-controlled via `prctl(PR_SET_NAME)`.

## 11.3 Symlink and Container Root Evasion

**Threat:** Using a symlink, bind mount, or container filesystem layering trick so that a path *appears* to match policy from one namespace's view but resolves to different content.

**Mitigation:** Path resolution is performed against the fully resolved canonical path, evaluated in the correct mount/namespace context for the executing process (i.e., resolved from the process's own root, not the host's naive view of the path string), preventing a container from presenting a spoofed path to the host's policy engine.

## 11.4 Policy Tampering

**Threat:** An attacker with limited privilege attempts to add their malicious binary's path to CWP policy directly, self-granting containment immunity.

**Mitigation:** Policy modification requires the same administrative privilege boundary as other KBS security configuration (not exposed to unprivileged users or to the monitored workloads themselves), and cluster-synchronized policy is signed (§4.3) so a compromised host cannot forge fleet-wide policy that other hosts would trust.

## 11.5 Over-Broad Policy as a Self-Inflicted Risk

**Threat:** Not an external attacker, but an administrator (or an automated pipeline) accidentally defining an overly broad protected path (e.g., a whole directory or wildcard) that unintentionally shields unrelated or malicious processes.

**Mitigation:** Schema validation (§4.1) rejects overly broad patterns by default (e.g., disallows top-level wildcards like `/usr/bin/*`), requiring explicit, narrow, per-binary entries; broader patterns require an explicit `allow_broad: true` acknowledgment flag plus a mandatory justification string.

---

# 12. Configuration Examples

## 12.1 YAML

```yaml
critical_workloads:
  - path: /usr/bin/postgres
    identity_tier: path
    owner_team: data-platform
    justification: "Primary production OLTP database"

  - path: /usr/bin/vault
    identity_tier: hash
    expected_hash_source: build-pipeline   # hash fetched/verified from CI artifact registry
    owner_team: security-infra
    justification: "Secrets management; elevated identity verification required"

  - path: /opt/company/payment-service
    identity_tier: hash
    owner_team: payments
    justification: "PCI-scoped payment processing service"
    risk_threshold_override: 90   # only escalate/alert above this score

policy_metadata:
  version: 14
  signed_by: fleet-policy-signer-01
  revocation_mode: on_exit   # or "immediate" — see §12.2
```

## 12.2 TOML

```toml
[[critical_workloads]]
path = "/usr/bin/postgres"
identity_tier = "path"
owner_team = "data-platform"
justification = "Primary production OLTP database"

[[critical_workloads]]
path = "/usr/bin/containerd"
identity_tier = "path"
owner_team = "platform-infra"
justification = "Container runtime; required for cluster scheduling"

[policy_metadata]
version = 14
signed_by = "fleet-policy-signer-01"
revocation_mode = "on_exit"
```

### Revocation Modes

* `on_exit` (default): a workload removed from policy remains protected for any currently running instance until it next exits; new instances are unprotected immediately.
* `immediate`: currently running protected PIDs matching a removed policy entry are immediately de-registered from `protected_workloads_map` upon policy reload. This is a stricter, opt-in mode for organizations that want policy changes to take effect instantly, accepting the small risk of interrupting a running workload mid-session if the removal was in error.

---

# 13. Logging Examples

## 13.1 Registration Event

```text
[CWP] Workload Registered
Path: /usr/bin/postgres
PID: 2148
Identity Tier: path
Policy ID: 17
Owner Team: data-platform
```

## 13.2 Containment Rejection Event

```text
[CWP] Containment Prevented
PID: 2148
Process: postgres
Executable: /usr/bin/postgres
Reason: Administrator Protected Workload
Policy ID: 17
Owner Team: data-platform
```

## 13.3 Spoofed Identity Attempt (Security Event)

```text
[CWP] SECURITY EVENT — Identity Verification Failed
Path: /usr/bin/vault
PID: 8831
Identity Tier: hash
Expected Hash: 3f2a...c9
Observed Hash: 91bd...44
Action: NOT registered as protected — eligible for normal containment
```

## 13.4 Deregistration Event

```text
[CWP] Workload Deregistered
Path: /usr/bin/postgres
PID: 2148
Reason: Process Exit
```

---

# 14. Edge Cases

## 14.1 PID Reuse

**Risk:** A protected workload exits, its PID is not promptly removed from `protected_workloads_map`, and the kernel reassigns that PID to an unrelated (potentially malicious) process, which would incorrectly inherit protection.

**Handling:** The exit() BPF hook (§2.1, §6.1) synchronously removes the PID entry at process exit, before the PID can be recycled by the kernel's PID allocator under normal operation. As defense in depth, the exec() hook also re-validates identity on every new process start (§7) regardless of any stale map state, so even in a theoretical race, a non-matching new process at that PID is never treated as protected — protection is always identity-derived at exec time, never inherited from a stale PID entry.

## 14.2 Service Restart

**Risk:** A protected workload crashes and restarts, receiving a new PID; if protection depended solely on PID, the restarted service would be briefly unprotected.

**Handling:** Protection is anchored to executable identity (§5), not PID. The exec() hook re-registers the new PID at the moment of restart, and the startup reconciliation scan (§3.3) provides an additional safety net after any KBS or policy restart.

## 14.3 Orphaned Registry Entries

**Risk:** A BPF map entry for a PID persists after the process has exited without triggering the exit hook (e.g., due to a hook failure or an unclean sensor restart), leaving a stale "protected" entry pointing at a PID that may later be reused.

**Handling:** A periodic reconciliation sweep (distinct from startup reconciliation) walks `protected_workloads_map` and cross-checks each PID against `/proc` liveness; any PID no longer present in `/proc` is removed. This bounds the lifetime of any orphaned entry to the sweep interval even if the exit hook is missed.

## 14.4 Policy Removal While Workload Is Running

**Risk:** An administrator removes a workload from policy while instances are actively running.

**Handling:** Governed by `revocation_mode` (§12.2) — `on_exit` (default, safer) or `immediate` (opt-in, stricter). This is explicit, documented behavior rather than an implicit edge case, so operators can choose the trade-off deliberately.

## 14.5 Container Restarts with Ephemeral Paths

**Risk:** Containerized workloads may present executable paths that only exist inside a container's filesystem namespace, complicating host-level path resolution.

**Handling:** Identity resolution occurs within the executing process's own mount namespace context (§11.3), and policy entries for containerized workloads are expressed relative to the image's canonical in-container path, which remains stable across container restarts even though the container ID/PID changes.

---

# 15. Performance Considerations

* **Fast-path default:** the common case (path-tier match) is a single hash-table lookup during `exec()` — O(1) and negligible compared to the cost of `execve()` itself.
* **Hash-tier cost is bounded and rare:** binary hashing is only triggered for policy entries explicitly marked `identity_tier: hash`, which should be a small minority of entries (security-sensitive services), not the default for all workloads.
* **Hash caching:** to avoid re-hashing an unchanged binary on every restart, CWP caches `(device, inode, mtime) → hash` results; a hash is only recomputed when the underlying file's inode or modification time changes, keeping steady-state restart overhead close to the path-tier cost.
* **BPF map sizing:** `protected_workloads_map` is sized (8192 entries, §6.1) to comfortably exceed realistic protected-workload counts even in large microservice deployments, avoiding map-full errors that could otherwise cause protection registration to silently fail.
* **Reconciliation sweep cost:** the periodic orphan sweep (§14.3) is designed to run at a low frequency (e.g., every few minutes) and iterates only the protected-workload map (bounded by its max size), not the full system process table, keeping its overhead independent of total host process count.
* **Policy reload cost:** because reload uses an atomic snapshot swap (§4.1) rather than incremental mutation, reload cost is proportional to policy size, not to the number of currently running processes, and never blocks in-flight classification.

---

# 16. Sequence Diagrams

## 16.1 Workload Startup and Registration

```text
Admin           Policy Loader        exec() Hook        BPF Map           Process
  │                   │                    │                │                │
  │──add entry───────▶│                    │                │                │
  │                   │──validate/resolve─▶│                │                │
  │                   │──swap snapshot────▶│                │                │
  │                   │                    │                │                │
  │                   │                    │◀────execve()───┼────────────────│
  │                   │                    │──resolve path─▶│                │
  │                   │◀───lookup registry─│                │                │
  │                   │──match found──────▶│                │                │
  │                   │                    │──insert PID───▶│                │
  │                   │                    │                │──protected────▶│
```

## 16.2 Containment Attempt Against a Protected Workload

```text
Detection Engine     CPM              CWP              Containment Engine    Alerting
      │                │                │                       │              │
      │──recommend────▶│                │                       │              │
      │                │──check─────────│                       │              │
      │                │  (not protected│                       │              │
      │                │   by CPM)      │                       │              │
      │                │───────────────▶│                       │              │
      │                │                │──check protected──────│              │
      │                │                │  workloads_map         │              │
      │                │                │  → MATCH                │              │
      │                │                │──reject───────────────▶│              │
      │                │                │                       │──log/alert──▶│
      │                │                │                       │  (escalated) │
```

## 16.3 Process Exit and Deregistration

```text
Process              exit() Hook             BPF Map
   │                       │                      │
   │──exit()──────────────▶│                      │
   │                       │──delete PID entry───▶│
   │                       │                      │──removed
```

---

# 17. Benefits (Retained from Original Spec)

* Prevents production outages caused by false positives.
* Protects business-critical infrastructure.
* Preserves complete security visibility.
* Separates monitoring from enforcement.
* Allows organization-specific protection policies.
* Supports dynamic registration as workloads restart.
* Integrates with existing containment logic without modifying eBPF LSM programs.

---

# 18. Acceptance Criteria

CWP is considered successfully implemented when:

* Administrators can register protected workloads through signed, validated policy configuration (YAML or TOML).
* Protected executables automatically register their running PIDs at `exec()` time, and the startup/policy-reload reconciliation scan protects already-running instances.
* Identity resolution supports both path-tier and hash-tier verification, with hash-tier enforced for any policy entry marked accordingly.
* Registered workloads remain fully monitored by KBS — detection, telemetry, and forensic collection continue normally.
* Automatic containment and termination are prevented for protected workloads, evaluated strictly **after** CPM in the decision pipeline (§8).
* Elevated, severity-escalated alerts are generated whenever a protected workload triggers a detection event, including policy metadata (owner team, justification) in the alert.
* Workload protection persists across process restarts and is anchored to executable identity, not PID.
* PID entries are removed from `protected_workloads_map` on process exit, and a periodic reconciliation sweep removes any orphaned entries missed by the exit hook.
* Removing a workload from policy makes future instances eligible for normal containment, with running-instance behavior governed by an explicit, documented `revocation_mode`.
* Attempts to spoof a protected identity via binary replacement, process-name spoofing, or path/namespace tricks are detected and logged as distinct security events, and are never registered as protected.
* Policy tampering by unprivileged actors is prevented, and cluster-synchronized policy is signed and verified before being trusted by a host.

Critical Workload Protection extends the containment platform beyond operating system safety by introducing organization-aware protection policies. It allows enterprises to confidently deploy automated detection and containment while ensuring that essential production services remain continuously available, even during high-confidence security events — without weakening the structural guarantees provided by CPM.