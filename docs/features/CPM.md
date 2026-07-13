# Critical Process Module (CPM)

**Version:** 2.0
**Component:** Kernel Behaviour Sensor (KBS)
**Status:** Design Specification (Expanded)

---

# 1. Overview & Motivation (Expanded)

## 1.1 Purpose

The **Critical Process Module (CPM)** is a protection subsystem that sits between the detection/containment recommendation pipeline and the actual enforcement mechanism (`contained_pids_map` + eBPF LSM hooks). Its sole responsibility is to answer one question for every containment request:

> *"Is this process allowed to be contained, or would doing so put the operating system or the security platform itself at risk?"*

CPM does not perform detection, scoring, or threat classification. It is strictly an **authorization gate**. This separation of concerns keeps the containment engine free to be aggressive against genuinely malicious processes, while CPM independently guarantees that certain processes are categorically exempt regardless of how suspicious their behavior may appear.

## 1.2 Why This Problem Exists

Containment works by attaching restrictive eBPF LSM policies to a PID: blocking new file opens, blocking socket creation, blocking `execve()`, and in some configurations, enabling termination. This is an effective technique against malware, but it is indiscriminate by design — it does not understand *what* a process is, only that a detection engine flagged it.

This creates a structural risk: any component capable of recommending containment is also capable of *recommending containment of the operating system's own control plane*. A detection engine can be wrong. A behavioral heuristic can misfire. A rule can match a legitimate administrative script that looks like reconnaissance. When that happens against an ordinary user application, the result is an inconvenience. When it happens against `systemd`, a kernel worker thread, or the sensor itself, the result can be:

* A kernel panic (containment or termination of PID 1)
* A total loss of service management (systemd restarts blocked)
* A frozen or unresponsive host (core kernel threads restricted)
* A blind spot in security coverage (the sensor contains itself and stops reporting)

The last scenario is particularly dangerous because it is *self-defeating*: malware that can indirectly trigger containment logic against the sensor's own PID could use the security platform's own containment engine as a weapon against itself.

## 1.3 Design Goal

CPM's design goal is to make these failure modes **structurally impossible**, not merely unlikely. Rather than relying on the detection engine to "know better" than to flag critical infrastructure, CPM introduces a mandatory, independent checkpoint that every containment request must pass through — regardless of source, confidence score, or urgency.

---

# 2. Design Principles (New)

CPM is built around a small number of non-negotiable principles:

### 2.1 Authorization is separate from detection
CPM never evaluates *why* a process was flagged. It only evaluates *what* the process is. This keeps the two concerns cleanly decoupled: detection logic can evolve independently without ever needing to "remember" to exclude critical processes.

### 2.2 Fail closed toward protection
When classification is ambiguous or registry data is temporarily unavailable, CPM defaults to treating a process as protected rather than allowing containment. It is always safer to under-contain than to destabilize the host.

### 2.3 Protection must survive restarts
PIDs are ephemeral — a critical service that crashes and restarts receives a new PID. CPM's protection model is therefore anchored to durable identifiers (executable path, well-known PID such as 1, and kernel-thread structural properties) rather than to PID values alone.

### 2.4 No self-containment, ever
A security platform must be immune to disabling itself, whether by external attack or by its own false positives. Sensor components are unconditionally protected from the moment they start.

### 2.5 Every rejection is observable
A silent rejection is indistinguishable from a bug. Every time CPM blocks a containment request, it must produce an auditable record explaining what was blocked and why.

### 2.6 Minimal, fast-path evaluation
Because CPM sits directly in the containment decision path, its checks must be O(1) or close to it (map lookups, pointer checks) so that it introduces negligible latency into the enforcement pipeline.

---

# 3. Protected Process Categories (Expanded with Rationale)

## 3.1 Critical Operating System Processes

**Examples:** `systemd`, `systemd-logind`, `systemd-udevd`, `dbus-daemon`, `NetworkManager`

**Rationale:** These processes form the control plane of the operating system itself. `systemd` supervises all other services; `systemd-logind` manages sessions and power state; `systemd-udevd` manages device node creation; `dbus-daemon` brokers inter-process communication that many system services depend on; `NetworkManager` controls network connectivity, which containment tooling itself may depend on for reporting telemetry. Containing any of these can cascade into failures far outside the originally flagged process.

## 3.2 Kernel Threads

**Examples:** `[kworker]`, `[ksoftirqd]`, `[kthreadd]`, `[migration]`, `[rcu_*]`

**Rationale:** Kernel threads are not ordinary processes — they execute kernel-side work items (deferred interrupts, RCU grace-period management, CPU migration, workqueue processing) and have no associated userspace memory or executable image. LSM-based containment primitives such as blocking file opens or network syscalls are meaningless (and potentially destabilizing) when applied to kernel-space execution contexts. These are excluded structurally, not by name-matching, since kernel thread names are numerous and can vary by kernel version and configuration.

## 3.3 Sensor Components

**Examples:** `kb-sensor`, `kb-agent`, `kbctl`, `policy-engine`, `dashboard`

**Rationale:** These are the security platform's own components. If compromised behavior anywhere on the host could cause the platform to contain its own processes, an attacker (or a false positive) could blind the platform at the exact moment visibility matters most. Self-protection is therefore treated as a first-class security requirement, not an operational nicety.

## 3.4 Protected Executables

**Examples:** `/usr/lib/systemd/systemd`, `/usr/bin/dbus-daemon`, `/usr/bin/NetworkManager`

**Rationale:** Because PIDs are reassigned on every restart, protecting only a *current* PID is insufficient — a crashed and respawned `systemd-logind` would otherwise be unprotected until manually reclassified. Binding protection to the executable path guarantees that any process image known to be critical is automatically re-protected the instant it starts, with no dependency on human intervention or a stale PID list.

---

# 4. Architecture (Expanded)

## 4.1 High-Level Flow

```text
            Detection Engine
                   │
                   ▼
        Containment Recommendation
                   │
                   ▼
       Critical Process Module (CPM)
                   │
      ┌────────────┴────────────┐
      │                         │
 Protected                 Not Protected
      │                         │
      ▼                         ▼
 Reject Request        contained_pids_map
      │                         │
      ▼                         ▼
 Audit Log Event        eBPF LSM Enforcement
```

## 4.2 Placement in the Pipeline

CPM is deliberately positioned as the **last gate before enforcement**, not as a pre-filter inside the detection engine. This placement matters:

* It guarantees that *no path* to `contained_pids_map` exists that bypasses CPM, even if new detection sources are added later.
* It means CPM's logic can be validated, audited, and tested independently of whatever detection heuristics happen to exist in a given release.
* It allows CPM to be implemented once, in a single choke point, rather than duplicated across every possible caller of the containment engine.

## 4.3 Component Interaction

```text
┌──────────────────┐      ┌───────────────────┐      ┌─────────────────────┐
│  Detection Engine │ ---> │        CPM         │ ---> │  Containment Engine  │
│ (behavioral rules,│      │ (classifier +      │      │ (contained_pids_map │
│  ML scoring, etc.)│      │  registries)       │      │  + eBPF LSM hooks)   │
└──────────────────┘      └───────────────────┘      └─────────────────────┘
                                    │
                                    ▼
                           ┌─────────────────┐
                           │  Audit / Logging │
                           └─────────────────┘
```

CPM exposes a single decision function to callers: given a target PID (and optionally its executable path), it returns either `ALLOW` or `REJECT(reason)`. Callers never see or manipulate CPM's internal registries directly.

---

# 5. Implementation (Much More Detailed)

CPM consists of four cooperating components: two BPF maps, a userspace registry service, and a classifier routine invoked at containment-request time.

## 5.1 Protected PID Registry (BPF Map)

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);      // PID
    __type(value, u8);     // 1 = protected
    __uint(max_entries, 2048);
} protected_pids_map SEC(".maps");
```

* Only the **existence** of a key matters; the value is a sentinel.
* Sized generously (2048 entries) since protected processes are numerically small even on large hosts — this is not intended to scale with total process count, only with the count of critical infrastructure + sensor components.
* Entries are removed when the corresponding PID exits, to prevent PID-reuse from incorrectly protecting an unrelated later process (see §7.3).

## 5.2 Protected Executable Registry (Userspace)

Maintained outside the kernel as a userspace configuration structure, since path strings are variable-length and better suited to userspace matching before a single PID insertion is pushed into the BPF map.

```text
/usr/lib/systemd/systemd
/usr/bin/dbus-daemon
/usr/bin/NetworkManager
/usr/bin/kb-sensor
/usr/bin/kb-agent
/usr/sbin/kbctl
```

* Loaded at KBS startup from a signed, administrator-editable configuration file.
* Administrators may append additional paths for site-specific infrastructure (e.g., a custom orchestration agent) without modifying CPM's code.
* Matching is done against the resolved, canonical executable path (post-symlink-resolution) to prevent trivial bypass via symlink aliasing.

## 5.3 Registration Path: exec() Hook

```text
execve() syscall
        │
        ▼
LSM/BPF exec hook fires
        │
        ▼
Resolve canonical executable path
        │
        ▼
Path present in Protected Executable Registry?
        │
   ┌────┴────┐
  YES        NO
   │          │
   ▼          ▼
Insert PID   No action
into
protected_pids_map
```

This hook runs once per `exec()`, is O(1) against a hash-set lookup, and executes before the process has any opportunity to be evaluated for containment.

## 5.4 Process Classifier

The classifier is the function invoked synchronously whenever a containment recommendation arrives:

```c
enum cpm_decision {
    CPM_ALLOW,
    CPM_REJECT_KERNEL_THREAD,
    CPM_REJECT_PID1,
    CPM_REJECT_PROTECTED_PID,
    CPM_REJECT_PROTECTED_EXEC,
};

enum cpm_decision cpm_classify(struct task_struct *task) {
    if (task->mm == NULL)
        return CPM_REJECT_KERNEL_THREAD;

    if (task->pid == 1)
        return CPM_REJECT_PID1;

    if (bpf_map_lookup_elem(&protected_pids_map, &task->pid))
        return CPM_REJECT_PROTECTED_PID;

    if (exec_path_is_protected(task))
        return CPM_REJECT_PROTECTED_EXEC;

    return CPM_ALLOW;
}
```

* Checks are ordered from cheapest/most-structural (pointer null check) to most expensive (path resolution), so common cases resolve quickly.
* The first matching condition short-circuits evaluation — no further checks are performed once a rejection reason is found.

## 5.5 Concurrency & Consistency

* `protected_pids_map` is a BPF hash map, and all inserts/lookups use atomic BPF map operations — no separate locking is required.
* The userspace executable registry is read-mostly; updates (e.g., an administrator adding a new protected path) are applied via an atomic pointer swap so in-flight classifications are never evaluated against a half-updated registry.
* PID insertion (§5.3) and PID lookup (§5.4) may race under extremely tight timing (a process execs and is targeted for containment nearly simultaneously); CPM defaults to protection (`CPM_ALLOW` is never returned) whenever this specific race is detected via a re-check pattern before finalizing the enforcement decision.

---

# 6. Process Classification Flow (Expanded)

```text
                 ┌─────────────────────────┐
                 │ Containment Recommended  │
                 │        for PID X         │
                 └────────────┬─────────────┘
                              ▼
                 ┌─────────────────────────┐
                 │  task->mm == NULL ?      │───Yes──▶ REJECT: Kernel Thread
                 └────────────┬─────────────┘
                              │ No
                              ▼
                 ┌─────────────────────────┐
                 │      PID == 1 ?          │───Yes──▶ REJECT: PID 1
                 └────────────┬─────────────┘
                              │ No
                              ▼
                 ┌─────────────────────────┐
                 │ PID in protected_pids_map│───Yes──▶ REJECT: Protected PID
                 └────────────┬─────────────┘
                              │ No
                              ▼
                 ┌─────────────────────────┐
                 │ exec path in registry?   │───Yes──▶ Insert PID, REJECT: Protected Executable
                 └────────────┬─────────────┘
                              │ No
                              ▼
                 ┌─────────────────────────┐
                 │  ALLOW → contained_pids  │
                 └─────────────────────────┘
```

Each decision branch is independently unit-testable, and each carries a distinct, loggable rejection reason — there is no generic "denied" outcome; the specific category is always recorded.

---

# 7. Protection Registration Lifecycle (New)

## 7.1 Startup Registration

When KBS starts:

1. The Protected Executable Registry is loaded from configuration.
2. KBS enumerates its own running components (`kb-sensor`, `kb-agent`, `kbctl`, `policy-engine`, `dashboard`) and inserts their current PIDs into `protected_pids_map` immediately, before any detection or containment logic becomes active.
3. Critical OS processes already running at KBS startup are scanned (via `/proc`) and their PIDs are pre-registered if their executable path matches the registry, so protection is not delayed until their next restart.

## 7.2 Runtime Registration

For any process that starts *after* KBS is already running, registration happens reactively via the `exec()` hook described in §5.3 — there is no polling delay.

## 7.3 De-registration

To prevent PID-reuse from silently inheriting protection:

```text
Process exits
      │
      ▼
task exit hook fires
      │
      ▼
Remove PID from protected_pids_map (if present)
```

This ensures that once a protected process terminates, its PID number can later be reassigned to an unrelated ordinary process without that new process inheriting protected status.

## 7.4 Administrator-Designated Infrastructure

Administrators may mark additional executables or PIDs as protected through a controlled interface (e.g., `kbctl protect --path /opt/vendor/agent`). These entries are merged into the same registry and subject to the same lifecycle rules — they are not a separate code path.

---

# 8. Containment Decision Flow (Expanded)

```text
Containment Requested (PID X)
            │
            ▼
   ┌─────────────────┐
   │ CPM Classifier   │
   └────────┬────────┘
            │
   ┌────────┴─────────────────────────────┐
   │                                       │
 REJECT                                  ALLOW
   │                                       │
   ▼                                       ▼
Emit Audit Event                 Insert into contained_pids_map
   │                                       │
   ▼                                       ▼
Process remains fully               eBPF LSM Enforcement
monitored, uncontained              (restrictions applied)
```

Key properties of this flow:

* **Monitoring never stops.** A rejected process is not exempted from telemetry, alerting, or forensic logging — only from active containment. CPM narrows *enforcement*, not *visibility*.
* **No retry loop against CPM.** A rejected containment request is not silently retried; if the underlying detection condition persists, a new recommendation may be generated and will be re-evaluated independently, but CPM does not maintain any bypass or escalation path for repeated rejections.
* **Deterministic outcome.** Given the same process state, CPM always returns the same decision — there is no time-based or confidence-based override that can force containment of a protected process.

---

# 9. Logging & Audit Events (Expanded)

## 9.1 Event Schema

Every rejection produces a structured audit event containing:

| Field | Description |
|---|---|
| `timestamp` | Time of the containment request |
| `pid` | Target PID |
| `process_name` | Resolved process/comm name |
| `exec_path` | Canonical executable path, if resolvable |
| `reason` | One of: `PID1`, `KERNEL_THREAD`, `PROTECTED_PID`, `PROTECTED_EXECUTABLE` |
| `requesting_component` | Which detection source generated the original recommendation |

## 9.2 Example Events

```text
[CPM] Containment Prevented
PID: 1
Process: systemd
Reason: Critical Operating System Process
```

```text
[CPM] Containment Prevented
PID: 248
Process: [kworker/0:2]
Reason: Kernel Thread
```

```text
[CPM] Containment Prevented
PID: 9931
Process: kb-sensor
Reason: Sensor Self-Protection
```

## 9.3 Purpose of Logging

* **Incident response clarity:** Analysts reviewing an incident can immediately see that a suspicious process was correctly exempted from containment rather than assuming containment silently failed.
* **Debugging detection logic:** A spike in CPM rejections for a particular category (e.g., repeated rejections against `NetworkManager`) is a strong signal that upstream detection rules are misfiring and need tuning.
* **Compliance & forensics:** Audit trails demonstrate that protective controls functioned as designed, which is often a requirement in security certification and post-incident review processes.

## 9.4 Retention & Forwarding

Audit events are forwarded through the same telemetry pipeline used for other KBS security events, ensuring they are retained under existing log-retention policies and are queryable alongside detection and containment events for full-lifecycle incident reconstruction.

---

# 10. Benefits

* Prevents accidental operating system instability caused by containment of core OS processes.
* Structurally protects kernel infrastructure, independent of name-based heuristics, via the `task->mm == NULL` check.
* Guarantees the security platform cannot disable itself through self-containment.
* Automatically re-protects critical services across restarts without manual reclassification.
* Cleanly separates authorization (CPM) from enforcement (containment engine), simplifying reasoning about and testing each independently.
* Adds negligible performance overhead due to O(1) map-lookup-based classification.
* Preserves full monitoring and forensic visibility even for processes that are exempt from containment.
* Provides a clear, auditable record of every protective decision for incident response and compliance purposes.

---

# 11. Acceptance Criteria

CPM is considered successfully implemented when:

* Every containment request passes through CPM before any modification to `contained_pids_map`.
* PID 1 is permanently and unconditionally protected.
* Kernel threads are automatically excluded from containment via structural detection (`task->mm == NULL`), not name-matching.
* Sensor components register themselves as protected at startup and cannot be contained under any circumstance.
* Protected executables automatically register newly created PIDs at `exec()` time, with no dependency on manual reclassification after restarts.
* Protected PIDs are removed from `protected_pids_map` on process exit to prevent PID-reuse from inheriting protection.
* Protected processes continue to generate full telemetry, alerts, and forensic events despite being exempt from containment.
* Every rejected containment request produces a structured, retained audit event including PID, process name, executable path, and rejection reason.
* Only non-protected userspace processes are ever inserted into `contained_pids_map` and reach the eBPF LSM enforcement pipeline.
* Administrator-designated protected infrastructure follows the same registration and lifecycle rules as built-in protected categories.

CPM ensures that the containment engine remains aggressive against malicious userspace processes while guaranteeing that critical operating system infrastructure and the security platform itself remain stable and continuously operational.