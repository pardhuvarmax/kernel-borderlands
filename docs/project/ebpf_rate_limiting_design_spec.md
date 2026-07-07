# eBPF Rate-Limiting and Performance Design Specification

This document details the aligned design architecture for Ring 0 dynamic event rate-limiting, event prioritization, and graceful degradation in the C sensor (`kb-core`).

---

## 1. Core Principles: Graceful Degradation under Overload

Dropping security telemetry events is inherently risky. Under extreme load, rather than failing blindly or dropping events indiscriminately, Kernel Borderlands implements a **graceful degradation** model designed around these core tenets:

1. **Intelligent Information Loss**: Never drop high-value security events. Focus throttling and aggregation strictly on low-value repetitive operations.
2. **Telemetry Loss Accounting**: Maintain strict accounting of lost or aggregated events so the userspace engine can factor uncertainty into process behavior analysis.
3. **Prevent Channel Starvation**: Prevent event storms from a single noisy process from blocking critical telemetry streams from other active processes.

---

## 2. Event Priority Classification Tiers

Events are classified into three distinct priority tiers within the eBPF kernel-space code:

| Tier | Priority | Event Types | Rate-Limiting Policy |
|---|---|---|---|
| **Tier 1** | **Critical (Non-Droppable)** | `Gain Root UID` (commit_creds), LSM denials (`-EACCES`), TLS write plaintext uprobes, memory injections (`process_vm_writev`), binary executions (`execve`). | **Always Transmit**. These events bypass the token bucket rate limiter and are always written to the ring buffer. |
| **Tier 2** | **Routine (Compressible)** | Repetitive file opens/reads/writes (sensitive paths excluded), socket connects, standard memory mappings (`mmap`, `mprotect`). | **Aggregate or Sample**. Under normal load, these are transmitted. Under overload, they are rolled up or throttled per-PID. |
| **Tier 3** | **Low-Value (High-Volume)** | Repetitive system configuration reads, benign context switches. | **Filtered at Source**. Suppressed directly in kernel-space based on local allowlist rules. |

---

## 3. Integration Workflow & Confidence Score Degradation

```mermaid
flowchart TD
    subgraph Kernel Space
        Event[Telemetry Event]
        Classify{Priority Tier?}
        Bucket[Token Bucket Check]
        Acc[Accumulate Drop Count]
        RB[Perf Ring Buffer]
    end
    
    subgraph Userspace Control Plane
        KBD[Go Control Plane Daemon]
        SM[Behavior State Machine]
        Conf[Reduce Threat Score Confidence]
    end
    
    Event --> Classify
    Classify -->|Tier 1| RB
    Classify -->|Tier 2| Bucket
    Bucket -->|Passed| RB
    Bucket -->|Throttled| Acc
    Acc -->|Flush Aggregate Log| RB
    RB -->|Stream| KBD
    KBD -->|Event Stream| SM
    KBD -->|Aggregate Drop Log| Conf
```

- **Uncertainty Propagation**: When the userspace engine receives a `KB_EVENT_DROPPED_TELEMETRY` summary packet containing the drop count for a specific PID, the Behavioral Scoring Engine automatically decreases its threat score confidence rating. This makes the potential information loss explicit to operators and downstream agents.

---

## 4. Kernel-Space Map Layout

```c
struct kb_token_bucket {
    __u64 last_time;
    __u64 tokens;
    __u64 dropped_count;
    __u32 priority_bypass; // Flag indicating if Tier 1 bypass is active
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct kb_token_bucket);
} kb_rate_limit_map SEC(".maps");
```
