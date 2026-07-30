# kb-op

**A complete, standalone unified interface product for Linux server workloads and security applications — CLI (`ctl`), TUI, and MCP, with its own built-in backend**

Status: full end-to-end project specification — designed to be built, shipped, and used entirely on its own
Track: Developer experience / Interfaces
Document version: 2.0

> **This is a whole product, not a piece of a bigger system.** Everything needed to build and ship this on its own — vision, architecture, tech stack, roadmap to v1.0 — is in this one document. Unlike a typical "just a CLI wrapper" project, kb-op owns its own backend (Chapter 8) so it doesn't require any other system to be useful. A solo engineer should be able to start a fresh repository, use nothing but this document, and build toward a working v1.0.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Vision & Mission](#2-vision--mission)
3. [Problem Statement & Motivation](#3-problem-statement--motivation)
4. [Landscape & Prior Art](#4-landscape--prior-art)
5. [Design Philosophy](#5-design-philosophy)
6. [Glossary of Terms](#6-glossary-of-terms)
7. [High-Level Architecture Overview](#7-high-level-architecture-overview)
8. [Built-in Local Backend Daemon — Deep Dive](#8-built-in-local-backend-daemon--deep-dive)
9. [`ctl` — CLI Client Deep Dive](#9-ctl--cli-client-deep-dive)
10. [`tui` — Terminal Console Deep Dive](#10-tui--terminal-console-deep-dive)
11. [`mcp` — Model Context Protocol Server Deep Dive](#11-mcp--model-context-protocol-server-deep-dive)
12. [Web Dashboard Deep Dive](#12-web-dashboard-deep-dive)
13. [SSH-Fronted Operator Access](#13-ssh-fronted-operator-access)
14. [Backend RPC Contract & Protobuf Service Definition](#14-backend-rpc-contract--protobuf-service-definition)
15. [Data Flow Walkthroughs](#15-data-flow-walkthroughs)
16. [Authorization Model](#16-authorization-model)
17. [Audit Logging Architecture](#17-audit-logging-architecture)
18. [Capability Catalog](#18-capability-catalog)
19. [Backend Swappability](#19-backend-swappability)
20. [State & Session Model](#20-state--session-model)
21. [TUI State Machine](#21-tui-state-machine)
22. [MCP Tool Contract Stability & Versioning](#22-mcp-tool-contract-stability--versioning)
23. [Tech Stack & Rationale](#23-tech-stack--rationale)
24. [Repository Layout & Build System](#24-repository-layout--build-system)
25. [Configuration Reference](#25-configuration-reference)
26. [Security Model & Threat Model](#26-security-model--threat-model)
27. [Performance Engineering](#27-performance-engineering)
28. [Reliability & Failure Modes](#28-reliability--failure-modes)
29. [Observability, Logging & Debugging](#29-observability-logging--debugging)
30. [Testing Strategy](#30-testing-strategy)
31. [Deployment & Packaging](#31-deployment--packaging)
32. [Operations Runbook](#32-operations-runbook)
33. [Roadmap to v1.0 and Beyond](#33-roadmap-to-v10-and-beyond)
34. [Worked Operator Walkthrough](#34-worked-operator-walkthrough)
35. [Troubleshooting & FAQ](#35-troubleshooting--faq)
36. [MCP Prompt Template Reference](#36-mcp-prompt-template-reference)
37. [Appendix A: Full `ctl` Command Reference](#appendix-a-full-ctl-command-reference)
38. [Appendix B: Full MCP Tool Reference](#appendix-b-full-mcp-tool-reference)

---

## 1. Executive Summary

`kb-op` is a self-contained operator platform for Linux server posture management. It ships four consumer-facing surfaces — a scriptable CLI (`ctl`), a live terminal console (`tui`), a Model Context Protocol server (`mcp`) for LLM agents and IDE assistants, and a browser dashboard for visualization — all backed by exactly one thing this project also owns and ships: a local backend daemon that reads real host state (`/proc`, `journald`, `auditd` logs) for live observability, takes direct OS-primitive action on individual processes (quarantine/release), and — its core distinguishing feature — runs a continuous **fabric reconciliation loop** that keeps a declared set of OS-posture domains (service state, hardening configuration, patch posture, log posture, scheduled tasks) converged against an operator- or agent-declared desired state.

The product thesis is simple: every other security operations tool forces you to choose between automation-friendly (CLI, but poor situational awareness), operator-friendly (a TUI or GUI, but hard to script), or agent-friendly (an API, usually bolted on last and inconsistently). `kb-op` refuses the choice — one backend, one authorization model, one audit trail, four front-ends that are each excellent at what they're good at and structurally incapable of drifting out of sync with each other, because none of them contain their own copy of the logic.

`kb-op` is deliberately **not** a security-tool adapter layer. It never speaks the native protocols of nftables, fail2ban, ClamAV, Suricata, or AppArmor/SELinux — that integration domain belongs to a separate, disjoint project (see §2.4). What `kb-op` owns is a different, non-overlapping category entirely: continuous OS-posture management expressed declaratively, plus the live interface layer on top of it.

This document specifies the whole thing end to end: what the backend daemon does and how, what each of the four interfaces looks like and how it talks to the backend, the RPC contract that binds them together, the authorization and audit model that makes the "safe for an LLM agent to drive too" claim actually true, and a phased roadmap from an empty repository to a packaged v1.0.

## 2. Vision & Mission

**Vision.** A server operator — human or AI — should never have to ask "which tool do I use for this," "will this action be logged the same way no matter how I did it," or "can I script what I just did by hand." One backend. One set of capabilities. Four doors into it, each built for how a different kind of consumer actually works.

**Mission statement.** Ship a single installable product that gives any Linux server a working, auditable, scriptable, LLM-accessible operator surface over its own live state and its own declared OS posture — without requiring any other software to be installed, deployed, or trusted first.

**Non-goals.**

- `kb-op` is not a detection engine. It observes what the host already exposes; it does not itself decide what is anomalous. (A more sophisticated detection/response system could sit behind the same backend contract later — see Chapter 19 — but that is explicitly out of scope for this project's v1.0.)
- `kb-op` is not a fleet management system. Every design decision in this document assumes a single host talking to its own local backend daemon over a Unix domain socket. Multi-host fleet orchestration is a plausible *future* extension, not a v1.0 requirement, and is called out wherever it would otherwise creep into scope.
- `kb-op` is not a security-tool adapter layer, and never becomes one. It does not speak nftables/iptables/firewalld/ufw's control surfaces, fail2ban's jail protocol, ClamAV's scan protocol, Suricata's alert/config surface, or AppArmor/SELinux's policy tooling. See §2.4.

### 2.4 Relationship to kb-cp

`kb-op` and a separate project, `kb-cp`, integrate with the host in genuinely disjoint ways, and this is intentional, not an oversight:

| | kb-cp | kb-op |
|---|---|---|
| Tool category | Established, named security software (nftables, fail2ban, ClamAV, Suricata, AppArmor/SELinux) | OS posture domains with no single "owning" security product (service state, hardening config, patch posture, log posture, scheduled tasks) |
| Integration paradigm | Imperative — call an adapter, get an immediate result | Declarative — declare desired state once, a reconciliation loop converges and re-converges continuously |
| Write surface for agents | General-purpose capability calls scoped by risk tier | A fixed, small catalog of templated intents (§18) — a narrower action space by design |
| Shared code or protocol with the other project | None | None |

If both projects exist in the same environment, they remain two independent daemons with no runtime dependency on each other — a host can run `kb-op` without `kb-cp` installed, and vice versa, and neither's absence degrades the other beyond the capabilities that are simply out of scope for the one that's missing. Anyone wanting to add "talk to a specific named security product" functionality should add it to kb-cp, not here — that boundary is what keeps this project's own scope from creeping back into duplicated adapter work.

## 3. Problem Statement & Motivation

Security operations tooling has historically forced an uncomfortable choice among three shapes, each of which is good at one thing and actively bad at the other two:

1. **Rich GUI / web dashboard.** Excellent for exploration — you can see a process tree, a graph of connections, a timeline of alerts. Terrible for automation: nobody wants to click through a dashboard in a CI pipeline, and "click here" is not a reproducible artifact you can put in a runbook or a Git diff.
2. **CLI.** Excellent for automation and repeatability — a `ctl` command is scriptable, diffable, and composable with the rest of a Unix toolchain. Poor for live situational awareness: polling a CLI in a loop to watch what's happening right now is a bad simulation of a live view.
3. **Bolted-on LLM/agent integration.** Increasingly common, and increasingly a liability when done last: an agent integration built after the "real" interfaces already exist tends to either wrap the CLI's text output (fragile — output format changes silently break the agent) or get its own thinner, less-audited path to the same underlying actions (dangerous — the agent ends up with *less* oversight than a human operator, exactly backwards from what you'd want).

The failure mode common to all three, when they're built as separate efforts rather than one project with multiple faces, is **drift**: the CLI supports an action the TUI doesn't, the TUI's quarantine flow logs differently than the CLI's, the MCP server exposes a tool that quietly stopped matching what the CLI does after a refactor nobody propagated. Each of these is a small bug individually. In aggregate, across a real deployment, they add up to "nobody actually knows what this system will do when you ask it to do something," which is precisely the property you cannot tolerate in anything that touches process isolation or a host's declared security posture.

A second, quieter failure mode specific to *posture* (as opposed to one-shot actions) is **silent drift-in-the-other-direction**: an operator hardens `sshd_config` by hand during an incident, and six months later a routine package upgrade or a well-meaning colleague's one-off `sed` quietly reverts it, and nobody notices until the next audit — or the next incident. A one-shot CLI command that "sets" a config value has no opinion about whether that value stays set. `kb-op`'s fabric model (§8) exists specifically to close this gap: desired state isn't just applied once, it's continuously asserted.

`kb-op`'s answer: don't build three-to-four tools that happen to target the same system. Build **one system** — the backend daemon — and four **thin, interchangeable doors** into it. A capability exists exactly once, in exactly one place, and every door that exposes it is structurally required to call the same code path to do it.

## 4. Landscape & Prior Art

No project needs to be built in a vacuum. The following existing tools are directly relevant reference points — each gets something right that `kb-op` deliberately borrows, and in a couple of cases, something worth explicitly not repeating.

| Project | What it gets right | What to borrow | What to avoid repeating |
|---|---|---|---|
| `kubectl` | Consistent verb/noun command grammar (`get`, `describe`, `delete` + resource type) scales to hundreds of subcommands without becoming unlearnable | Verb/noun grammar, `-o json`/`-o yaml` structured output convention, consistent exit-code semantics | Its plugin ecosystem sprawl — kb-op should keep its capability surface curated, not infinitely pluggable via third-party binaries with no contract |
| `k9s` | A keyboard-driven live TUI over the same API `kubectl` uses — no separate "TUI backend," it's a first-class consumer of the same cluster API | The exact relationship this project wants between `tui` and the backend daemon: a full alternate front-end, not a wrapper around the CLI | Its own configuration/theming complexity — start minimal |
| Official MCP SDKs (Go / TypeScript / Python reference servers) | Clean separation of tools (actions), resources (read-only context), and prompts (reusable workflow templates) as three distinct primitives | That three-primitive model directly — Chapter 11 uses it as-is | Some reference servers under-specify authorization, assuming the MCP transport boundary itself is the security boundary — kb-op explicitly does not assume this (Chapter 16) |
| Terraform / Ansible (declarative convergence tools) | Desired-state diffing and idempotent convergence as the core primitive — you declare an end state, the tool figures out what needs to change | The core idea, directly — the fabric model (§8) is this pattern applied continuously rather than as a one-shot `apply` | Their batch, run-once-then-exit execution model and heavyweight DSLs — kb-op's reconciliation is a background daemon loop with a small, typed spec per fabric, not a general-purpose provisioning language |
| `systemd` unit files | Declarative "this is the state this thing should be in" as a first-class OS concept, already familiar to every Linux operator | The mental model — a fabric's desired-state document should feel as natural as writing a unit file, not like learning a new configuration-management platform | Its complexity around ordering/dependency directives — a fabric spec stays intentionally flatter |
| `docker`/`docker compose` CLI | Extremely low friction for the 80% case (`docker ps`, `docker logs`) while still exposing full control for the 20% case | Sensible defaults with escape hatches (`--json` opts into machine output; humans get a table by default) | Its historical single-daemon-as-root model — kb-op's backend daemon should run with the minimum privilege each fabric provider actually needs, not blanket root |
| `htop` / `btop` | Extremely fast perceived responsiveness for a live process view, minimal input latency | The rendering discipline (Chapter 27) — a live TUI must never visibly stutter on a normal host | N/A — narrow scope tool, not a broader reference for the RPC/auth layers |
| SSH itself | The access-control-at-the-transport-boundary pattern: your identity is established once, at connection time, by a mechanism (public-key auth) that is itself extremely well understood | Using SSH as the operator-access transport rather than inventing a new auth handshake (Chapter 13) | N/A |

## 5. Design Philosophy

Four principles govern every design decision in this document. Where a later chapter seems to contradict one of these, the later chapter is wrong and should be revised — these are load-bearing, not aspirational.

> **One capability, one implementation, N front-ends.** If `ctl`, `tui`, and `mcp` each need their own logic for "what does declaring a fabric actually do," something is architected wrong. That logic belongs in the backend daemon, and all four interfaces are thin RPC callers — full stop. No interface is permitted to contain business logic that isn't equally available to the others through the same RPC method.

> **Same authorization everywhere.** An MCP tool call, a `ctl` command, and a TUI keypress that all resolve to the same backend RPC method must be subject to the exact same permission checks, evaluated in the exact same code path. No interface gets a shortcut, and critically, no interface gets a *narrower* check either — an LLM agent calling `apply_intent` via MCP must clear the same bar a human typing `ctl intent apply` does, not a lower one.

> **Audit at the point of the RPC call, not per-interface.** If auditing is implemented separately in the CLI, the TUI, and the MCP server, one of them will eventually drift and under-log — this is not a hypothetical, it is the default outcome of duplicated logic maintained by different people at different times. Audit centrally, in the backend, at the exact point where an action actually executes (including a fabric drift correction the reconciliation loop applies on its own — see §17.1), so it is structurally impossible for any interface, or the loop itself, to bypass it.

> **Terminal-first, browser-optional.** Every capability that matters operationally must be reachable and usable from `ctl` or `tui` alone, with no browser required. The web dashboard is allowed to add pure visualization value on top (a force-directed process graph, a historical chart) but must never be the *only* way to do something operationally important — an operator SSH'd into a headless box with no browser access must never be blocked.

## 6. Glossary of Terms

| Term | Definition |
|---|---|
| **Backend daemon** | The single long-running process this project ships that owns all host state reads, all direct process actions, and the fabric reconciliation loop. Everything else is a client of it. |
| **Capability** | One discrete, named action or query the backend exposes (e.g. `quarantine_process`, `list_processes`, `declare_fabric`). The unit of authorization and audit. |
| **Fabric** | A declared desired-state spec over one OS-posture domain — e.g. service-state, hardening, patch-posture, log-posture, scheduled-tasks (§8.3). |
| **Fabric provider** | The OS-family-specific implementation that knows how to observe and converge one fabric — e.g. the `systemd` provider for the service-state fabric, with an `OpenRC`/`rc.d` provider as an alternative on systems that use it. |
| **Fabric drift** | A detected divergence between a fabric's declared desired state and its currently observed actual state. Drift is logged as an audit event whether or not it has yet been corrected. |
| **Reconciliation loop** | The backend's continuous background process that, per enabled fabric and on its own interval, observes actual state, diffs it against declared state, and converges (§8.4). |
| **Intent** | A fixed, named, parameter-bounded action from the templated intent catalog (§18) — the agent-safe write path that touches one fabric without requiring the caller to author a full desired-state document. |
| **RPC** | Remote Procedure Call — here, a typed method call made by a client (`ctl`, `tui`, `mcp`, dashboard) to the backend daemon over gRPC. |
| **UDS** | Unix Domain Socket — a local, filesystem-path-addressed socket used for same-host IPC; faster and more easily permissioned than a TCP loopback socket. |
| **MCP** | Model Context Protocol — an open protocol for exposing tools, resources, and prompts to LLM-based clients in a structured, discoverable way. |
| **MCP tool** | An MCP primitive representing a callable action with a defined input schema and output shape — kb-op's MCP tools are 1:1 wrappers around backend RPC methods. |
| **MCP resource** | An MCP primitive representing readable, addressable context (not an action) — e.g. "current fabric status" as a resource an agent can read without "calling" anything. |
| **MCP prompt** | An MCP primitive representing a reusable prompt template for a common workflow (e.g. "investigate this PID") that an agent or IDE can surface to a user. |
| **Session** | A live, stateful connection from `tui` (or occasionally a long-running `mcp` client) to the backend daemon, over which streaming updates are pushed. |
| **Risk tier** | kb-op's blast-radius classification for a capability, fabric declare, or intent — gates which ones require extra confirmation (Chapter 16). |
| **Fabric spec format** | One of the supported input formats for authoring a fabric's desired state — `.yaml` (baseline), `.conf`, `.fabric` (native), `.lua` (sandboxed, programmable), or an optional Nix flake reference. All resolve to the same internal `DesiredState` before reaching the reconciliation loop (§8.7). |

## 7. High-Level Architecture Overview

```mermaid
flowchart TB
    subgraph Interfaces["kb-op interfaces (thin RPC clients)"]
        CTL["ctl — CLI"]
        TUI["tui — terminal console"]
        MCP["mcp — MCP server"]
        DASH["web dashboard"]
    end

    subgraph Backend["Built-in local backend daemon"]
        API["RPC/API layer<br/>gRPC over UDS, WebSocket stream"]
        AUTHZ["Authorization layer"]
        AUDIT["Audit logger"]
        CORE["Capability implementations<br/>process actions and fabric operations,<br/>shared by all callers"]
        RECON["Reconciliation loop"]
        PREG["Fabric provider registry"]
    end

    subgraph HostState["Host state sources, read-only"]
        PROC["/proc"]
        JOURNAL["journald log tail"]
        AUDITD_LOG["auditd log tail"]
    end

    subgraph Providers["Fabric providers — OS posture, not security tools"]
        SVC["systemd / OpenRC"]
        HARD["sshd_config / sysctl / PAM"]
        PATCH["apt / dnf / pkg"]
        LOGP["journald config"]
        CRONP["cron / systemd-timer"]
    end

    CTL -->|gRPC unary| API
    TUI -->|gRPC plus WebSocket stream| API
    MCP -->|gRPC unary, wraps as MCP tools| API
    DASH -->|WebSocket stream| API

    API --> AUTHZ --> CORE
    CORE --> AUDIT
    CORE --> RECON
    RECON --> PREG

    PREG --> SVC
    PREG --> HARD
    PREG --> PATCH
    PREG --> LOGP
    PREG --> CRONP

    CORE --> PROC
    CORE --> JOURNAL
    CORE --> AUDITD_LOG
```

Reading this diagram: every interface terminates at the same RPC/API layer. Nothing downstream of that layer knows or cares which interface originated a call. Authorization and audit sit structurally *between* the API layer and the capability implementations, so no capability — and no fabric drift correction the reconciliation loop applies on its own — can happen without passing through both. Note that the "Providers" subgraph contains only OS-posture mechanisms, never a named security product; that boundary is the entire point of §2.4.

## 8. Built-in Local Backend Daemon — Deep Dive

This is the chapter that makes the rest of the document real. Without a working backend, `ctl`/`tui`/`mcp`/dashboard are four clients pointed at nothing.

### 8.1 Responsibilities

The backend daemon has exactly three jobs, described precisely so scope doesn't creep:

1. **Read host state** and expose it as structured data over RPC: running processes (from `/proc`), recent security-relevant log events (from `journald` and `auditd`'s own log output), and the live convergence status of every enabled fabric.
2. **Take direct OS-primitive action on individual processes** on behalf of an authorized, audited RPC call: quarantine (isolate via cgroup/network-namespace restriction) or release a specific process. This is a live, one-shot incident-response action, not a declared posture, and it does not go through any fabric provider.
3. **Continuously reconcile declared fabrics** (§8.3): observe each enabled fabric's actual state, diff it against its declared desired state, converge, and log every correction.

Everything else in this document is in service of exposing those three jobs safely, consistently, and fast.

### 8.2 Internal structure

```mermaid
flowchart LR
    subgraph Daemon["kb-opd — backend daemon process"]
        direction TB
        RPC["RPC server<br/>gRPC + WS"]
        AZ["Authorizer"]
        REG["Capability registry"]
        AUD["Audit writer"]
        PS["Process source<br/>/proc poller"]
        LOGS["Log source<br/>journald + auditd tail"]
        RECON["Reconciliation loop<br/>ticks every fabric on its own interval"]
        PREG["Fabric provider registry"]
        PSVC["service-state provider"]
        PHARD["hardening provider"]
        PPATCH["patch-posture provider"]
        PLOG["log-posture provider"]
        PCRON["scheduled-tasks provider"]
    end

    RPC --> AZ --> REG
    REG --> AUD
    REG --> PS
    REG --> LOGS
    REG --> RECON
    RECON --> PREG
    PREG --> PSVC
    PREG --> PHARD
    PREG --> PPATCH
    PREG --> PLOG
    PREG --> PCRON
```

- **RPC server**: accepts gRPC unary calls (for one-shot capability invocations) and upgrades to a WebSocket or gRPC server-streaming call for anything that needs live push (process list changes, new alerts, fabric status changes).
- **Authorizer**: a single function every RPC handler calls before doing anything else — see Chapter 16.
- **Capability registry**: a table mapping capability name → implementation function + risk tier + required permission. This is the single source of truth for "what can this daemon do" — Chapter 18's catalog is generated from this table, not maintained separately by hand.
- **Audit writer**: appends a structured record for every capability invocation and every fabric drift correction, success or failure — see Chapter 17.
- **Process source**: polls `/proc/[pid]/*` on an interval (default 1s, configurable) and diffs against the previous snapshot to produce process-appeared / process-exited events for streaming consumers.
- **Log source**: tails `journald` via its native API (not by shelling out to `journalctl -f` and parsing text) and tails `auditd`'s own log output, normalizing both into one internal event shape. This is read-only observability — kb-op never writes to `auditd`'s rule configuration; that would be kb-cp's job (§2.4), not this project's.
- **Reconciliation loop and fabric provider registry**: see §8.3–§8.5.

### 8.3 The fabric model

A **fabric** is a declared desired-state spec over one OS-posture domain. This project ships five:

| Fabric ID | Domain | What "desired state" looks like | Primary Linux provider | Optional BSD provider |
|---|---|---|---|---|
| `service-state` | systemd/OpenRC-managed unit enable, running, masked state | "`sshd` must be enabled and running; `telnet.socket` must be masked" | `systemd` (D-Bus API) | `OpenRC` / `rc.d` |
| `hardening` | `sshd_config`, `sysctl`, PAM stack where available | "reject password auth; `net.ipv4.conf.all.rp_filter=1`" | Linux hardening provider (config-file + sysctl API) | BSD hardening provider (sshd_config + sysctl subset — PAM omitted where absent) |
| `patch-posture` | Automatic security-update policy, patch drift | "automatic security updates on; no package more than 14 days behind its security advisory" | `apt` / `dnf` | `pkg` |
| `log-posture` | `journald` retention, forwarding, rate-limit config | "retain 30 days; forward to the fleet's syslog collector; no rate-limit drop on `authpriv`" | `journald` | `syslog-ng`/`rsyslog` (subset) |
| `scheduled-tasks` | `cron` / `systemd-timer` job presence | "these three jobs must exist with these schedules; no other root crontab entries" | `cron` / `systemd-timer` | `cron` (same provider family) |

Each fabric's spec is a small, typed desired-state document — deliberately not a general-purpose provisioning language (see the Terraform/Ansible row in Chapter 4). A fabric spec describes an end state; it never describes steps, even in its one programmable authoring format (§8.7's `.lua` tier computes an end-state document, it does not script a sequence of changes). The example below is shown as YAML for illustration; §8.7 covers the other three supported authoring formats, all resolving to the same internal representation.

```yaml
# example desired-state document for the "hardening" fabric, shown in YAML for illustration — see §8.7 for other formats
fabric: hardening
version: 1
spec:
  ssh:
    password_authentication: false
    max_auth_tries: 3
    allowed_cidrs: ["10.0.0.0/8"]
  sysctl:
    net.ipv4.conf.all.rp_filter: "1"
    kernel.dmesg_restrict: "1"
```

### 8.4 Provider abstraction and the reconciliation loop

Every fabric provider — regardless of which OS family or underlying mechanism it wraps — implements one small interface:

```go
// internal/fabric/provider.go — illustrative, not complete
type State map[string]any // fabric-specific desired/actual state representation

type Drift struct {
    Field    string
    Desired  any
    Actual   any
    Severity string // "info", "warn", "high" — independent of the fabric's own risk tier
}

type Provider interface {
    Name() string                                    // e.g. "systemd", "openrc"
    Observe(ctx context.Context) (State, error)       // read actual state
    Diff(desired, actual State) []Drift               // compute drift, no side effects
    Apply(ctx context.Context, desired State) error   // converge actual toward desired
}
```

The reconciliation loop, one goroutine per enabled fabric, runs on a fixed interval (default 30s, per-fabric configurable, §25):

```go
// internal/reconcile/loop.go — illustrative, not complete
func (l *Loop) tick(ctx context.Context, f *Fabric) {
    actual, err := f.Provider.Observe(ctx)
    if err != nil {
        l.audit.RecordProviderError(f.ID, err) // provider unreachable is itself an audited event
        return
    }
    drift := f.Provider.Diff(f.DesiredState, actual)
    if len(drift) == 0 {
        return // converged, nothing to do this tick
    }
    if err := f.Provider.Apply(ctx, f.DesiredState); err != nil {
        l.audit.RecordDriftCorrectionFailed(f.ID, drift, err)
        return
    }
    l.audit.RecordDriftCorrected(f.ID, drift) // logged even though no human/agent triggered this specific tick
}
```

> **Design rationale.** Reconciliation runs on its own ticker, entirely separate from the RPC request path (§27.2) — a slow or stuck provider `Observe()` call must never block an unrelated `ctl` command from returning promptly. This is the same "don't let one slow thing stall an unrelated fast thing" principle already applied elsewhere in this document's sibling projects, just scoped to background convergence instead of a telemetry/control split.

Drift correction is never silent: every tick that applies a change writes an audit record (§17.1), even though the human or agent who *declared* the fabric may be long gone from the session by the time a correction actually fires, sometimes minutes, hours, or days later.

### 8.5 Provider registry and discovery

At startup, the daemon probes the host to determine its OS family and available mechanisms (presence of `systemd` vs. an `OpenRC`/`rc.d` init system, `apt` vs. `dnf` vs. `pkg`, PAM availability) and selects one provider per fabric accordingly, or marks that fabric `unavailable` if no provider matches. `ctl fabric list` (and the equivalent MCP resource) reports this explicitly — `unavailable: no supported init system provider detected`, never a silent gap. This matters as much for the MCP surface as capability discovery ever did for a tool-adapter model (§8 in earlier tool-adapter designs; the concern carries over unchanged even though the underlying mechanism does not): an LLM agent must be able to discover what it can and cannot declare on this specific host without trial and error.

### 8.6 Process model

The daemon is a single OS process. It runs as a dedicated system user (`kb-op`), not root, with narrowly scoped capabilities granted per fabric provider's actual need (e.g. the ability to write `/etc/ssh/sshd_config` granted only to the hardening provider's file-write path, not to the whole daemon) rather than running the whole daemon with blanket root — see Chapter 26 for the full privilege model.

### 8.7 Fabric spec formats & loaders

A fabric's desired-state document (§8.3 showed one as YAML, the baseline format) can also be authored in three additional formats, each suited to a different authoring style. This is purely an *input-layer* concern: every format resolves to the same internal `DesiredState` representation before the reconciliation loop, the RPC contract, or any provider ever sees it — none of those layers know or care which format an operator wrote.

```mermaid
flowchart LR
    YAML[".yaml file, baseline"]
    CONF[".conf file"]
    FABRIC[".fabric file"]
    LUA[".lua script"]
    NIX["Nix flake, optional"]
    LOADER["FabricLoader,<br/>selected by file extension"]
    DS["DesiredState,<br/>format-agnostic"]
    RECON["Reconciliation loop"]

    YAML --> LOADER
    CONF --> LOADER
    FABRIC --> LOADER
    LUA --> LOADER
    NIX -.->|optional build tag| LOADER
    LOADER --> DS
    DS --> RECON
```

The same `service-state` fabric (§8.3) — enable and run `sshd`, mask `telnet.socket` — expressed in each format:

**`.conf`** — a flat, low-ceremony key=value/INI format, easiest to hand-edit or generate from an existing config-management tool. Subsections follow the familiar `git config`-style quoted-name convention so a unit name containing a dot (`telnet.socket`) isn't ambiguous with INI's own section nesting:

```ini
[fabric]
name = service-state
version = 1

[unit "sshd"]
enabled = true
running = true

[unit "telnet.socket"]
masked = true
```

**`.fabric`** — this project's native format, and the richest of the four: structured blocks in the spirit of an nginx or systemd unit file, with first-class support for imports and per-provider overrides that the flatter formats can't express cleanly:

```
fabric "service-state" {
    version = 1

    unit "sshd" {
        enabled = true
        running = true
    }

    unit "telnet.socket" {
        masked = true
    }

    provider "openrc" {
        # OpenRC has no unit-masking concept — this block maps
        # "masked" onto a disabled + blocked service script instead,
        # only when the openrc provider is the one actually selected (§8.5)
        unit "telnet.socket" {
            disabled = true
        }
    }
}

import "./common-units.fabric"
```

**`.lua`** — the programmable tier, for desired state that needs to be computed rather than typed out statically (e.g. "enable this unit only on hosts in this role"). The daemon embeds a small, sandboxed Lua runtime purely for this evaluation:

```lua
-- fabric.lua — evaluated in a sandboxed Lua runtime, no filesystem or network access
local role = host.role  -- injected, read-only context; not a filesystem read

local desired = {
  fabric = "service-state",
  version = 1,
  units = {
    sshd = { enabled = true, running = true },
    ["telnet.socket"] = { masked = true },
  },
}

if role == "bastion" then
  desired.units["node_exporter"] = { enabled = true, running = true }
end

return desired
```

> **Sandboxing, specifically.** The embedded Lua runtime loads no `os`/`io` standard-library tables, so a script has no filesystem or network access from within the evaluation — it can only read the constrained, injected `host` context (role, hostname, OS family) and return a plain data structure. Evaluation runs under a hard timeout (default 500ms) so a runaway or infinite-looping script can't hang the daemon. The returned value is validated against the exact same `DesiredState` schema every other format produces — a Lua script cannot return something that bypasses schema validation just because it came from code instead of a static file.

**Nix flakes** — optional and feature-flagged (built with `-tags nix`), for operators who want fully reproducible, hermetically-evaluated desired state. Unlike the three loaders above, which evaluate in-process, this one shells out to `nix eval <flake-ref>#fabricOutputs.service-state --json` and treats the result as a `DesiredState` document. A build without the `nix` tag treats a flake reference as an unrecognized input and `ctl fabric declare` fails clearly at load time, rather than silently ignoring it.

> **Tradeoff, stated plainly.** Nix buys genuine reproducibility — the exact same flake input evaluates to the exact same desired state on any machine, with dependency pinning Nix already does well. The cost is a heavy toolchain dependency (a working Nix installation) and a slower, shell-out-based evaluation path with a larger interpreter surface than the sandboxed in-process Lua option. That's why this loader is optional and off by default rather than core: most deployments don't need Nix-grade reproducibility for a handful of fabric specs, and the ones that do already have Nix as part of their stack anyway.

### 8.8 The loader abstraction

```go
// internal/fabric/loader.go — illustrative, not complete
type DesiredState map[string]any // resolved, format-agnostic representation

type FabricLoader interface {
    Load(ctx context.Context, path string) (DesiredState, error)
}

var loaders = map[string]FabricLoader{
    ".yaml":   yamlLoader{},   // baseline format, used for illustration throughout this document
    ".yml":    yamlLoader{},
    ".conf":   confLoader{},
    ".fabric": fabricLoader{}, // native format: imports, per-provider overrides
    ".lua":    luaLoader{},    // sandboxed evaluation, see §8.7
    // ".nix" / flake references only registered when built with -tags nix
}
```

`ctl fabric declare -f <path>` (§9) selects a loader purely by file extension and resolves to `DesiredState` before the file ever reaches an RPC call — `DeclareFabric` (§14) always transmits an already-resolved `DesiredState`, never a raw file, so the RPC contract, the capability catalog, and the reconciliation loop stay entirely format-agnostic and none of those chapters needed to change to add this input layer.

### 8.9 Progressive expressiveness: compilation, not decompilation

The four formats aren't four equally-interchangeable ways to write the same thing — they split cleanly into two kinds, and conversion between them is asymmetric on purpose:

```mermaid
flowchart LR
    CONF[".conf"]
    FABRIC[".fabric"]
    LUA[".lua"]
    NIX["Nix flake"]

    CONF <--> FABRIC
    FABRIC --> LUA
    FABRIC --> NIX
```

| From → To | Supported | Mechanism |
|---|---|---|
| `.conf` → `.fabric` | Yes, lossless | Both parse to the same `DesiredState`; a `FabricFormatter` serializes back out to either syntax |
| `.fabric` → `.conf` | Yes, lossless | Same formatter, opposite direction |
| `.fabric` → `.lua` | Yes, one-way | `ctl fabric compile --to lua` emits a static script whose `return` is the literal desired-state table |
| `.fabric` → `.nix` | Yes, one-way | `ctl fabric compile --to nix` emits a flake fragment with the equivalent attrset |
| `.conf` → `.lua` / `.nix` | Yes, via `.fabric` | `.conf` → `.fabric` (lossless) → compile (one-way); same two-step path either way |
| `.lua` → `.fabric` / `.conf` | **No** | A script's logic (branching on `host.role`, computed values) doesn't generally reduce to a static document |
| Nix flake → `.fabric` / `.conf` | **No** | Same reason, plus a flake's own external inputs aren't reconstructable outside Nix |

> **Why the asymmetry is correct, not a gap.** `.conf` and `.fabric` are declarative *data* — two syntaxes over the exact same schema, so round-tripping between them is just re-serialization, no information is lost either direction. `.lua` and `.nix` are *programs* that *produce* a `DesiredState` when evaluated — every declarative document can trivially be re-expressed as a program that returns it (that's what `fabric compile` does), but the reverse doesn't generally hold, the same way compiling source to a binary is mechanical while decompiling a binary back to equivalent source is not. `fabric compile` is deliberately named "compile," not "convert," for exactly this reason — it signals a one-way operation, so nobody expects `ctl fabric compile --to fabric hardening.lua` to exist.

This asymmetry isn't just policy — it's enforced at the type level. §8.8's `FabricLoader` interface is one-way (`path → DesiredState`) and every format implements it. Only `.conf` and `.fabric` additionally implement a second interface that can run in reverse:

```go
// internal/fabric/format.go — illustrative, not complete
type FabricFormatter interface {
    Format(ds DesiredState) ([]byte, error) // DesiredState -> source text
}

var formatters = map[string]FabricFormatter{
    ".conf":   confFormatter{},
    ".fabric": fabricFormatter{},
    // .lua and .nix intentionally have no entry here — there is nothing
    // for them to implement; a compiled .lua/.nix file is an output of
    // fabricFormatter-adjacent codegen (see fabricCompiler below), not
    // something DesiredState can be reconstructed from.
}

// One-way codegen, not a Formatter: fabric-or-conf DesiredState -> program source.
// There is no corresponding luaLoader-reversing or nixLoader-reversing type.
type fabricCompiler interface {
    CompileTo(ds DesiredState, target string) ([]byte, error) // target: "lua" | "nix"
}
```

`ctl fabric convert <path> --to conf|fabric` exists (round-trip, lossless, either direction) precisely because a `FabricFormatter` exists for both sides. `ctl fabric compile <path> --to lua|nix` exists as a one-way command with no `--from lua`/`--from nix` counterpart, because no formatter — and therefore no reverse path — exists for those two targets. The CLI's command surface mirrors the type system exactly; there's no reverse command to forget to add later, because there's no interface it could be built on.

## 9. `ctl` — CLI Client Deep Dive

### 9.1 Command taxonomy

`ctl` follows a verb-scoped-by-noun grammar, one level deeper than `kubectl`'s flat noun-then-verb where doing so improves clarity for a security operations vocabulary:

```
ctl <resource> <verb> [args] [flags]

ctl process list
ctl process describe <pid>
ctl process quarantine <pid> [--reason "..."]
ctl process release <pid>

ctl fabric list
ctl fabric declare <fabric-id> -f <desired-state.yaml> [--reason "..."] [--dry-run]
ctl fabric status <fabric-id>
ctl fabric drift [--fabric <id>] [--since 24h]
ctl fabric convert <path> --to conf|fabric              # lossless, either direction
ctl fabric compile <path> --to lua|nix                  # one-way, .conf/.fabric source only

ctl intent list
ctl intent apply <intent-name> [--param key=value ...] [--reason "..."]

ctl audit query --since 1h --severity high
ctl audit export --format json --out audit.json
ctl audit verify

ctl capability list
ctl backend status
```

### 9.2 Flag conventions

- `--json` on any read command switches output from a human-formatted table to newline-delimited or array JSON — never a hybrid, never "pretty JSON by default, `--json` makes it uglier"; JSON output is always machine-oriented (no color codes, no box-drawing characters).
- `--reason` is required (not optional) on every capability, fabric declare, or intent whose risk tier is `high` or above (Chapter 16) — the CLI itself enforces this client-side as a fast-fail UX nicety, in addition to the backend enforcing it authoritatively.
- `--yes`/`-y` skips an interactive confirmation prompt for high-risk actions; without it, a TTY session prompts, a non-TTY (CI) invocation fails closed and requires the flag explicitly — never silently proceeds without a human or an explicit flag in an unattended context.
- `--dry-run` on `ctl fabric declare` computes and prints the diff against current actual state without storing the new desired state or triggering any convergence — the `low`-tier preview path referenced in Chapter 16.
- `-f`/`--file` on `ctl fabric declare` accepts a path in any supported fabric spec format (`.conf`, `.fabric`, `.lua`, or an optional Nix flake reference — §8.7); the loader is selected by file extension and the rest of the pipeline never knows which format was used.
- `ctl fabric convert` and `ctl fabric compile` (§8.9) are the only two commands whose supported directions are asymmetric on purpose: `convert` runs either way between `.conf` and `.fabric`, `compile` only runs from `.conf`/`.fabric` source toward `.lua`/`.nix`, never the reverse.
- Exit codes: `0` success, `1` generic failure, `2` authorization denied, `3` backend unreachable, `4` invalid arguments. Scripts can branch on these without parsing text.

### 9.3 Illustrative command implementation sketch

```go
// cmd/ctl/fabric.go — illustrative, not complete
var declareCmd = &cobra.Command{
    Use:   "declare <fabric-id>",
    Short: "Declare desired state for a fabric",
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        fabricID := args[0]
        specPath, _ := cmd.Flags().GetString("file")
        spec, err := os.ReadFile(specPath)
        if err != nil {
            return fmt.Errorf("reading spec file: %w", err)
        }
        reason, _ := cmd.Flags().GetString("reason")
        tier := riskTierForFabric(fabricID) // looked up from the capability registry
        if tier >= RiskHigh && reason == "" {
            return fmt.Errorf("--reason is required for fabric %q at tier %s", fabricID, tier)
        }
        if dryRun, _ := cmd.Flags().GetBool("dry-run"); dryRun {
            return printDiffOnly(cmd.Context(), fabricID, spec)
        }
        if !cmd.Flags().Changed("yes") && isInteractive() && tier >= RiskHigh {
            if !confirm(fmt.Sprintf("Declare fabric %q? [y/N] ", fabricID)) {
                return nil
            }
        }
        client := backend.MustConnect()
        resp, err := client.DeclareFabric(cmd.Context(), &pb.DeclareFabricRequest{
            FabricId:     fabricID,
            DesiredState: spec,
            Reason:       reason,
        })
        if err != nil {
            return mapRPCError(err) // translates gRPC status -> ctl exit code
        }
        printResult(resp, jsonFlag(cmd))
        return nil
    },
}
```

### 9.4 Output formatting

Table output uses fixed-width columns with a documented, stable column order per resource type (documented in Chapter 25's reference alongside config, not repeated per-command) — a script that greps column 3 of `ctl process list` today should still find the same field in a year, or the column order change should be flagged as a breaking change in the changelog.

## 10. `tui` — Terminal Console Deep Dive

### 10.1 Layout

```
┌─ kb-op ─────────────────────────────────────────────── host: web-03 ─┐
│ [1] Processes   [2] Alerts   [3] Fabrics   [4] Query   [?] Help       │
├─────────────────────────────────────────────────────────────────────┤
│  PID    USER      CPU%   MEM%   STATE     COMMAND                     │
│  1044   www-data  2.1    0.8    running   nginx: worker process       │
│  1102   root      0.0    0.3    running   sshd: operator [priv]       │
│  2211   app       14.7   3.2    running   python3 worker.py           │
│  ...                                                                   │
├─────────────────────────────────────────────────────────────────────┤
│ ⚠ 3 alerts in last 15m  •  fabrics: 4/5 in sync, 1 drifted  •  next  │
│ reconcile in 12s                                                      │
├─────────────────────────────────────────────────────────────────────┤
│ > _                                              [q]uit [/]search      │
└─────────────────────────────────────────────────────────────────────┘
```

- **Header bar**: current host, top-level view tabs, always visible.
- **Main pane**: the active view (process table, alert feed, fabric status list, or an interactive query console).
- **Status bar**: a persistent, always-on summary of the most operationally relevant live counters (active alerts, fabric sync state, time to next reconciliation tick) so an operator glancing at any view still has situational awareness without switching tabs.
- **Command line**: a `:`-prefixed or `/`-prefixed command line (vim-style) for issuing the same capabilities `ctl` exposes, without leaving the TUI.

### 10.2 Keyboard model

| Key | Action |
|---|---|
| `1`–`4` | Switch top-level view |
| `j`/`k` or arrows | Move selection |
| `Enter` | Open detail view for selected row |
| `q` | Quarantine selected process (prompts for reason, then confirmation) |
| `/` | Enter search/filter mode for the current view |
| `:` | Enter command mode (full capability access via typed command) |
| `Ctrl-R` | Force refresh / reconnect to backend |
| `?` | Help overlay listing all bindings for the current view |
| `Esc` | Cancel current input / close overlay |

*Within the Fabrics view specifically:*

| Key | Action |
|---|---|
| `Enter` | Open fabric detail: desired vs. actual side-by-side, current drift list |
| `a` | Open the intent picker and apply a suggested remediation intent for the selected drift |
| `r` | Force an immediate reconciliation tick for the selected fabric, without waiting for its next scheduled interval |

No destructive keybinding fires immediately on a single keypress without a confirmation step — this is a deliberate, non-negotiable UX rule given what these actions do (Chapter 26 covers why blast-radius-aware confirmation matters even for a human directly at the keyboard).

### 10.3 Rendering approach sketch

```rust
// illustrative — not complete
fn render(frame: &mut Frame, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // header
            Constraint::Min(3),     // main pane
            Constraint::Length(1),  // status bar
            Constraint::Length(1),  // command line
        ])
        .split(frame.size());

    render_header(frame, chunks[0], app);
    match app.active_view {
        View::Processes => render_process_table(frame, chunks[1], &app.processes),
        View::Alerts    => render_alert_feed(frame, chunks[1], &app.alerts),
        View::Fabrics   => render_fabric_status(frame, chunks[1], &app.fabrics),
        View::Query     => render_query_console(frame, chunks[1], &app.query_state),
    }
    render_status_bar(frame, chunks[2], app);
    render_command_line(frame, chunks[3], &app.command_line);
}
```

### 10.4 Live updates

`tui` opens one persistent streaming RPC to the backend on launch and applies incoming diffs (process appeared/exited, new alert, fabric status changed) directly to in-memory view state — it does not poll. See Chapter 20 for the session/streaming model and Chapter 27 for the render-latency budget this implies.

### 10.5 Alert-focused view mockup

Pressing `Enter` on a row in the alert feed switches the main pane into a detail view for that alert, without leaving the surrounding chrome:

```
┌─ kb-op ─────────────────────────────────────────────── host: web-03 ─┐
│ [1] Processes   [2] Alerts   [3] Fabrics   [4] Query   [?] Help       │
├─────────────────────────────────────────────────────────────────────┤
│ ALERT #a91f — HIGH — 14:22:07                                         │
│                                                                         │
│  Source:    auditd (rule: unexpected-setuid)                          │
│  Process:   2211 (python3 worker.py), uid transition 1000 -> 0        │
│  Host:      web-03                                                    │
│  Related:   3 audit records in the last 60s (press 'r' to view)       │
│                                                                         │
│  Suggested actions:                                                   │
│   [q] Quarantine pid 2211                                             │
│   [i] Open investigate_process prompt for pid 2211                    │
│   [Esc] Back to alert feed                                            │
├─────────────────────────────────────────────────────────────────────┤
│ ⚠ 3 alerts in last 15m  •  fabrics: 4/5 in sync, 1 drifted            │
├─────────────────────────────────────────────────────────────────────┤
│ > _                                              [q]uit [/]search      │
└─────────────────────────────────────────────────────────────────────┘
```

The detail view's "suggested actions" are not a separate code path — `q` here invokes the exact same `QuarantineProcess` RPC as the process-table binding in §10.2, and `i` surfaces the same `investigate_process` MCP prompt template defined in Chapter 36, rendered as a guided text flow inside the TUI rather than requiring a separate agent client. Reusing the prompt template here, instead of writing bespoke TUI investigation logic, is a direct application of the one-capability-one-implementation principle (Chapter 5) — the guided investigation flow is authored once and is usable from an LLM client or from a human sitting at the TUI.

### 10.6 Command-mode overlay mockup

Pressing `:` opens a bottom-anchored overlay with tab-completion over the full capability, fabric, and intent catalog (Chapter 18), so an operator never has to leave the keyboard-driven flow to reach something with no dedicated keybinding:

```
┌─ kb-op ─────────────────────────────────────────────── host: web-03 ─┐
│ [1] Processes   [2] Alerts   [3] Fabrics   [4] Query   [?] Help       │
├─────────────────────────────────────────────────────────────────────┤
│  (main pane dimmed, previous view still visible underneath)           │
├─────────────────────────────────────────────────────────────────────┤
│ :intent apply harden-ssh --param disallow_password_auth=true          │
│  --reason "CIS baseline enforcement"                                  │
│ ┌───────────────────────────────────────────────────────────────┐   │
│ │ intent apply harden-ssh [--param k=v ...] [--reason "..."]      │   │
│ │   Apply the harden-ssh templated intent.  risk tier: high       │   │
│ └───────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│ [Tab] complete  [Enter] execute  [Esc] cancel                        │
└─────────────────────────────────────────────────────────────────────┘
```

Because the entered line is `high` risk tier, executing it does not fire immediately on `Enter` — per the no-single-keypress-destructive-action rule (§10.2), it drops into the same `ConfirmPending` state shown in the TUI state machine (Chapter 21) before the backend ever sees the RPC call.

## 11. `mcp` — Model Context Protocol Server Deep Dive

### 11.1 Why MCP, specifically

An LLM agent or IDE assistant needs a *discoverable, typed* way to know what it can do and what it's looking at — free-text CLI help output is not a reliable contract for a model to parse. MCP's three primitives map cleanly onto what this project already has:

- **Tools** → capabilities that do something: process actions, fabric declares, and — the primary agent-facing write path — `apply_intent` calls against the fixed intent catalog (§18).
- **Resources** → capabilities that are pure reads, exposed as addressable, subscribable context rather than "calls" (current process list, current fabric status and drift, recent alert digest).
- **Prompts** → reusable workflow templates ("investigate process", "review fabric drift") that bundle several tool/resource reads into a suggested reasoning flow a client can surface to its user.

### 11.2 Illustrative tool definition

```json
{
  "name": "quarantine_process",
  "description": "Quarantine a running process on the host, isolating it from further execution and network access via a direct OS-level primitive (cgroup and network-namespace restriction). Requires a reason. This is a high-risk action subject to the same authorization and audit as an operator running `ctl process quarantine`.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "pid": { "type": "integer", "description": "Process ID to quarantine" },
      "reason": { "type": "string", "description": "Human-readable justification, required" }
    },
    "required": ["pid", "reason"]
  }
}
```

### 11.3 Resource examples

| Resource URI | Contents |
|---|---|
| `kbop://processes` | Current process list snapshot, same shape as `ctl process list --json` |
| `kbop://alerts/recent` | Alerts from the last 15 minutes, severity-sorted |
| `kbop://fabrics` | Every enabled fabric's ID, provider, sync state, and current drift count |
| `kbop://fabrics/{fabric_id}/drift` | The full current drift list for one fabric, field-by-field |
| `kbop://intents` | The fixed templated-intent catalog (§18), each with its schema and risk tier |
| `kbop://capabilities` | The live capability- and provider-availability table from §8.5 — critical for an agent to self-discover what's actually usable on this host |

### 11.4 Prompt template example

```json
{
  "name": "investigate_process",
  "description": "Guided investigation of a specific process: pulls process detail, recent related audit events, and open network connections, then suggests next steps.",
  "arguments": [
    { "name": "pid", "description": "Process ID to investigate", "required": true }
  ]
}
```

### 11.5 Non-negotiable rule

> This is the single most important sentence in this chapter: **the MCP server enforces the exact same authorization and audit-logging as every other interface, with zero exceptions.** An LLM agent must never have a shortcut around controls a human operator would be subject to. Concretely: the MCP server is implemented as an RPC client identical in privilege to `ctl` — it does not get a bypass flag, a service-account superuser token, or a separate lower-friction code path. If a capability requires confirmation for a human, the equivalent MCP tool call requires the `reason` field and is gated by the same risk-tier check server-side (Chapter 16), regardless of what the calling agent does or doesn't do client-side. Additionally — and this is specific to kb-op's design, not a general MCP requirement — an agent's *only* write path into fabric state is `apply_intent` against the fixed catalog; `declare_fabric` is exposed as an MCP tool too, but at a deliberately higher default risk tier than any single intent, precisely because a full desired-state document is a much larger action space than one bounded, named intent (§26.2 covers why this distinction matters).

### 11.6 Transport

The MCP server speaks standard MCP transport (stdio for local IDE-integration use, or HTTP+SSE for networked agent clients) on its front, and is itself just another gRPC client of the backend daemon on its back — see Chapter 7's diagram. It holds no state of its own beyond what's needed to translate MCP requests into backend RPC calls and responses back.

## 12. Web Dashboard Deep Dive

### 12.1 Purpose and scope

The dashboard exists strictly for visualization that a terminal genuinely cannot do well: a force-directed graph of process/network relationships, a historical time-series chart of alert volume, a timeline of fabric drift events. It is explicitly **not** where any operationally important action should be exclusively available — per the terminal-first principle (Chapter 5), everything the dashboard can trigger must also be reachable from `ctl`/`tui`.

### 12.2 Views

| View | Content |
|---|---|
| Overview | Host summary tiles (process count, alert count, fabrics in sync vs. drifted, patch-posture drift count), sparkline trends |
| Process graph | Force-directed graph, nodes = processes, edges = parent/child + observed network connections |
| Alert timeline | Historical, filterable, zoomable alert volume over time by severity |
| Fabric drift timeline | Historical view of drift events and corrections per fabric, useful for spotting a config that keeps getting reverted by something outside kb-op's control |

### 12.3 Data path

The dashboard connects over WebSocket for live tiles/timeline updates and issues normal unary gRPC-Web (or a thin REST shim over the same backend RPCs) for anything request/response-shaped like loading historical data for a custom time range. It carries no independent business logic — every number on screen traces back to a backend RPC response.

## 13. SSH-Fronted Operator Access

### 13.1 Rationale

Rather than exposing the backend daemon's RPC port on the network and inventing a bespoke auth handshake for remote `tui` access, `kb-op` uses SSH itself as the access-control transport: an embedded, hardened SSH service accepts connections, authenticates via public key only (no password fallback, ever), and on success spawns a `tui` session attached to that connection's PTY. The operator never touches the raw RPC socket directly over the network — SSH access *is* the auth boundary, and SSH's own well-understood security properties (key-based identity, host-key pinning against MITM) are reused rather than reinvented.

### 13.2 Design

```mermaid
sequenceDiagram
    participant Op as Operator ssh client
    participant SSHD as kb-op embedded SSH service
    participant TUI as tui process
    participant BD as Backend daemon

    Op->>SSHD: SSH connect, public-key auth
    SSHD->>SSHD: verify against authorized_keys
    SSHD-->>Op: auth accepted
    SSHD->>TUI: allocate PTY, spawn tui, attach stdio to session
    TUI->>BD: connect over local UDS, already-privileged local socket
    BD-->>TUI: stream process, alert, and fabric status updates
    TUI-->>Op: rendered terminal UI over the SSH session
```

### 13.3 Key management

- Host keys: persistent Ed25519 keypair generated once at install time and stored at a fixed, root-owned path — persistent host keys avoid MITM warnings on operator reconnection, which matters because an operator who's trained to click through host-key-changed warnings has been trained to ignore the one time it's real.
- Client authorization: a standard `authorized_keys`-format file, one key per authorized operator, no password authentication path compiled in at all (not merely disabled by default — this removes an entire class of credential-stuffing risk from the product).
- Session logging: every SSH session (source IP, key fingerprint, session duration) is logged independently of the audit log described in Chapter 17 — this is connection-level logging, not action-level, and both are needed.

## 14. Backend RPC Contract & Protobuf Service Definition

### 14.1 Service sketch

```protobuf
// illustrative excerpt — not the complete service definition
syntax = "proto3";
package kbop.v1;

service KbOp {
  rpc ListProcesses(ListProcessesRequest) returns (ListProcessesResponse);
  rpc StreamProcesses(StreamProcessesRequest) returns (stream ProcessEvent);
  rpc QuarantineProcess(QuarantineProcessRequest) returns (ActionResult);
  rpc ReleaseProcess(ReleaseProcessRequest) returns (ActionResult);

  rpc DeclareFabric(DeclareFabricRequest) returns (FabricStatus);
  rpc GetFabricStatus(GetFabricStatusRequest) returns (FabricStatus);
  rpc ListFabrics(ListFabricsRequest) returns (ListFabricsResponse);
  rpc ListFabricDrift(ListFabricDriftRequest) returns (ListFabricDriftResponse);
  rpc ApplyIntent(ApplyIntentRequest) returns (ActionResult);

  rpc QueryAuditLog(QueryAuditLogRequest) returns (QueryAuditLogResponse);
  rpc StreamAlerts(StreamAlertsRequest) returns (stream AlertEvent);

  rpc ListCapabilities(ListCapabilitiesRequest) returns (ListCapabilitiesResponse);
  rpc GetBackendStatus(GetBackendStatusRequest) returns (BackendStatus);
}

message FabricStatus {
  string fabric_id = 1;
  string desired_state = 2;   // serialized fabric-specific spec
  string actual_state = 3;    // last-observed state
  repeated Drift drift = 4;
  string last_reconciled = 5; // RFC3339 timestamp
}

message Drift {
  string field = 1;
  string desired = 2;
  string actual = 3;
  string severity = 4; // info, warn, high
}

message ActionResult {
  bool success = 1;
  string message = 2;
  string audit_id = 3;   // correlates the action to its audit-log entry
}
```

### 14.2 Design rules for the contract

- Every mutating RPC returns an `audit_id` so a caller (and a human reading a log later) can always tie an action's result back to the exact audit record for it — see Chapter 17.
- Every mutating RPC accepts a `reason` field; it is required server-side for any capability, fabric declare, or intent at risk tier `high` or above regardless of whether the calling client also enforces it (defense in depth, per Chapter 16).
- `DeclareFabric` is idempotent — redeclaring an already-converged desired state is a no-op against current actual state; only genuine drift produces a new correction and its own audit record.
- `ApplyIntent` never accepts free-form parameters beyond an intent's declared schema (§18) — this is what keeps the agent-facing write surface bounded, distinct from `DeclareFabric`'s larger action space (§11.5, §26.2).
- Streaming RPCs (`StreamProcesses`, `StreamAlerts`) use gRPC server-streaming for gRPC-native clients (`tui`, `mcp` where long-lived) and are also exposed over a WebSocket gateway for the dashboard, translating the same underlying event stream rather than maintaining two implementations of it.
- The `.proto` files are the single source of truth for the contract; all four clients generate their bindings from the same files, in CI, so a contract change that isn't reflected in a client fails the build rather than silently shipping a mismatch.

## 15. Data Flow Walkthroughs

### 15.1 `ctl fabric declare` end to end

```mermaid
sequenceDiagram
    participant U as Operator
    participant CTL as ctl
    participant API as Backend RPC layer
    participant AZ as Authorizer
    participant CORE as DeclareFabric capability
    participant RECON as Reconciliation loop
    participant PROV as hardening provider
    participant AUD as Audit writer

    U->>CTL: ctl fabric declare hardening -f ssh-hardening.yaml --reason CIS baseline
    CTL->>CTL: validate file, confirm, TTY prompt, high tier
    CTL->>API: gRPC DeclareFabric fabric_id=hardening, desired=..., reason=...
    API->>AZ: check caller identity and fabric risk tier
    AZ-->>API: authorized
    API->>CORE: execute
    CORE->>AUD: write audit record, declare accepted
    AUD-->>CORE: audit_id
    CORE-->>API: FabricStatus, desired stored, reconciling
    API-->>CTL: response
    CTL-->>U: Fabric hardening declared, audit d4e1a2, reconciling
    Note over RECON,PROV: runs on its own interval, independent of the RPC call above
    RECON->>PROV: Observe
    PROV-->>RECON: actual state
    RECON->>RECON: Diff desired against actual
    RECON->>PROV: Apply desired state for any drifted fields
    PROV-->>RECON: converged
    RECON->>AUD: write drift-correction record
```

### 15.2 MCP `apply_intent` end to end

```mermaid
sequenceDiagram
    participant Agent as LLM agent
    participant MCP as mcp server
    participant API as Backend RPC layer
    participant AZ as Authorizer
    participant CORE as ApplyIntent capability
    participant PROV as hardening provider
    participant AUD as Audit writer

    Agent->>MCP: call tool apply_intent, name harden-ssh, params disallow_password_auth true
    MCP->>MCP: validate against tool inputSchema and the fixed intent catalog
    MCP->>API: gRPC ApplyIntent name=harden-ssh, params=..., reason=...
    API->>AZ: check caller identity, mcp service identity, and intent risk tier
    AZ-->>API: authorized, same check as the ctl path, no bypass
    API->>CORE: execute
    CORE->>PROV: apply bounded, templated change only
    PROV-->>CORE: applied
    CORE->>AUD: write audit record, caller mcp, agent session id, reason, result
    CORE-->>API: ActionResult
    API-->>MCP: response
    MCP-->>Agent: tool result, success true, audit a4f091
```

The two diagrams above are deliberately different in shape past the client's own request-shaping step — that difference *is* the design: a declarative desired-state change reconciles asynchronously over time, while a templated intent applies immediately and synchronously, matching the smaller, more bounded change it represents.

## 16. Authorization Model

### 16.1 Identity

Every RPC caller is identified before any capability executes:

- `ctl` and `tui`, connecting over local UDS, are identified via `SO_PEERCRED` — the kernel-verified UID of the connecting process — mapped to an operator identity via a local identity/role file (or, for multi-operator hosts, backed by system groups).
- `mcp`, when running as a local stdio-transport server, is identified the same way (it's just another local process). When running as a networked HTTP+SSE server for remote agent access, callers authenticate via a scoped bearer token issued out-of-band, mapped to a distinct "agent" identity class that is never granted a broader role than the least-privileged human operator role by default.

### 16.2 Risk tiers

| Tier | Examples | Required |
|---|---|---|
| `read` | list processes, get fabric status, list fabric drift, list intents, query audit log | Valid identity only |
| `low` | `ctl fabric declare --dry-run` (preview diff, no state change) | Valid identity + operator role |
| `medium` | declare `service-state`/`patch-posture`/`log-posture`/`scheduled-tasks` fabrics; apply `enforce-auto-updates`, `ensure-unit-enabled`, `set-log-retention` intents | Valid identity + operator role, logged |
| `high` | quarantine/release a process; declare the `hardening` fabric; apply `harden-ssh` or `mask-unit` intents | Valid identity + operator role + `reason` field populated + logged with elevated detail |
| `critical` | (reserved for future capabilities with fleet- or host-wide blast radius, e.g. a fleet-wide fabric rollback) | Everything `high` requires, plus explicit two-step confirmation even for scripted callers (a `--confirm-critical` flag that must match a value printed by a prior dry-run call) |

### 16.3 Enforcement point

> Authorization is evaluated exactly once per RPC call, inside the backend daemon, before the capability implementation runs — never inside a client. A client-side check (like `ctl`'s confirmation prompt) is a UX nicety for the human at the keyboard, not a security control; the backend must independently re-verify everything, because a client cannot be trusted to have checked correctly, or at all, or to not have been modified.

## 17. Audit Logging Architecture

### 17.1 What gets logged

Every capability invocation, every `DeclareFabric`/`ApplyIntent` call, and every fabric drift correction the reconciliation loop applies on its own — success or failure, `read` tier or `critical` tier — produces one structured audit record: timestamp, caller identity (or `reconciliation-loop` as the actor for an unattended correction), capability or fabric name, input parameters, the `reason` field if present, the result, and a monotonically chained hash linking it to the previous record.

> **Design rationale.** Logging unattended drift corrections under a distinct `reconciliation-loop` actor identity, rather than attributing them to whoever last declared the fabric, matters for exactly the "silent drift-in-the-other-direction" failure mode described in §3: an operator reading the audit log six months later needs to be able to tell "I declared this" apart from "the daemon quietly put it back for the fourth time this month," because the second pattern is itself a signal worth investigating — something outside kb-op keeps fighting the declared state.

### 17.2 Tamper-evidence

Each audit record includes a hash of the previous record, so the log forms a hash chain — an attacker (or a compromised backend) who edits or deletes a historical record breaks the chain from that point forward, which is detectable by an independent verification pass (`ctl audit verify`) that any operator can run without needing to trust the daemon that wrote the log. The chain does not by itself *prevent* tampering (that requires write-once storage or remote log shipping, both noted as v1.0+ hardening options in Chapter 33) — it makes tampering **detectable**, which is the property that actually matters for a security tool's own audit trail.

### 17.3 Query and export

`ctl audit query` and the equivalent MCP resource (`kbop://audit/recent`) support filtering by time range, capability or fabric, caller, and severity. `ctl audit export` produces a portable, independently-verifiable export (records + chain) suitable for handing to an external SIEM or a compliance reviewer.

## 18. Capability Catalog

The following tables are generated from the backend's capability registry (§8.2) — this is the canonical list of what kb-op can do, and how each surfaces on each interface. Any capability, fabric, or intent added to the registry must add a row here in the same change.

### 18.1 Fabrics

| Fabric | Domain | `ctl` | `tui` | MCP | Dashboard |
|---|---|---|---|---|---|
| `service-state` | systemd/OpenRC unit enable, running, masked | `ctl fabric declare service-state -f ...` | Fabrics view | `declare_fabric` (tool), `kbop://fabrics` (resource) | Overview tile |
| `hardening` | sshd_config, sysctl, PAM where available | `ctl fabric declare hardening -f ...` | Fabrics view | `declare_fabric` (tool) | — |
| `patch-posture` | auto security-update policy, patch drift | `ctl fabric declare patch-posture -f ...` | Fabrics view | `declare_fabric` (tool) | Overview tile, patch drift count |
| `log-posture` | journald retention, forwarding, rate-limit | `ctl fabric declare log-posture -f ...` | Fabrics view | `declare_fabric` (tool) | — |
| `scheduled-tasks` | cron / systemd-timer job presence | `ctl fabric declare scheduled-tasks -f ...` | Fabrics view | `declare_fabric` (tool) | — |

### 18.2 Templated intents — the agent-safe write path

| Intent | Params | Fabric touched | Risk tier |
|---|---|---|---|
| `harden-ssh` | `disallow_password_auth` bool, `allowed_cidrs` list, `max_auth_tries` int | `hardening` | `high` |
| `enforce-auto-updates` | `enabled` bool, `security_only` bool | `patch-posture` | `medium` |
| `mask-unit` | `unit_name` string | `service-state` | `high` |
| `ensure-unit-enabled` | `unit_name` string, `running` bool | `service-state` | `medium` |
| `set-log-retention` | `retention_days` int, `forward_to` string (optional) | `log-posture` | `medium` |
| `ensure-cron-absent` | `job_id` string | `scheduled-tasks` | `medium` |
| `ensure-cron-present` | `job_id` string, `schedule` string, `command` string | `scheduled-tasks` | `high` (arbitrary command scheduling is inherently higher-risk than the other intents) |

### 18.3 Direct process actions and observability

| Capability | Risk tier | `ctl` command | `tui` binding | MCP tool/resource | Dashboard view |
|---|---|---|---|---|---|
| List processes | `read` | `ctl process list` | Processes view (default) | `kbop://processes` (resource) | Overview, process graph |
| Describe process | `read` | `ctl process describe <pid>` | `Enter` on selected row | `describe_process` (tool) | Process graph node click |
| Quarantine process | `high` | `ctl process quarantine <pid>` | `q` | `quarantine_process` (tool) | — (terminal-first only) |
| Release process | `high` | `ctl process release <pid>` | `r` (on quarantined row) | `release_process` (tool) | — |
| List fabrics | `read` | `ctl fabric list` | Fabrics view | `kbop://fabrics` (resource) | Overview tiles |
| Get fabric drift | `read` | `ctl fabric drift` | Fabrics view detail | `kbop://fabrics/{id}/drift` (resource) | Fabric drift timeline |
| List intents | `read` | `ctl intent list` | `:` command-mode tab-complete | `kbop://intents` (resource) | — |
| Query audit log | `read` | `ctl audit query` | `:audit query ...` | `kbop://audit/recent` (resource) | Alert timeline (as annotations) |
| Export audit log | `read` | `ctl audit export` | `:audit export ...` | — (export is a client-side operation on query results) | — |
| Verify audit chain | `read` | `ctl audit verify` | — | — | — |
| List capabilities | `read` | `ctl capability list` | `?` help overlay includes this | `kbop://capabilities` (resource) | — |
| Backend status | `read` | `ctl backend status` | Status bar (always visible) | `kbop://status` (resource) | Overview tiles |

## 19. Backend Swappability

The RPC contract (Chapter 14) is defined independently of the built-in backend's implementation. Any process that implements the same `.proto` service and speaks the same authorization/audit expectations can sit behind `ctl`/`tui`/`mcp`/dashboard in place of the built-in daemon. This is deliberately kept as an *optional* extension point, not a v1.0 requirement — the built-in backend (Chapter 8) is what ships and is what every interface is tested against. A future, more sophisticated backend (e.g. one doing fleet-wide correlation or ML-driven scoring) becoming available later is a plausible reason to use this extension point; it is explicitly not something v1.0 needs to anticipate beyond keeping the contract clean. Note that this swappability point is unrelated to kb-cp (§2.4) — a swapped-in backend still would not speak to named security tools directly under this project's contract; that integration category is out of scope here by design, not merely by current implementation status.

## 20. State & Session Model

### 20.1 `ctl`

Stateless, request/response only. Each invocation opens a connection, makes one or more RPC calls, and exits. No session persists between invocations beyond whatever the OS/shell environment carries (e.g. a configured default backend socket path).

### 20.2 `tui`

Opens one long-lived connection on launch, used for both unary calls (issuing an action) and a server-streaming subscription (receiving live updates, including fabric status changes). On disconnect (network blip, backend restart), `tui` enters a visible "reconnecting" state (never silently shows stale data as if it were live — see Chapter 28) and resubscribes on reconnect, requesting a fresh full snapshot before resuming diffs.

### 20.3 `mcp`

Stateless per tool-call in the common case (stdio-transport, IDE-integrated use). For networked HTTP+SSE agent access, a session may persist across multiple tool calls within one agent conversation, but carries no privilege escalation across calls — each call is independently authorized as if it were the first.

## 21. TUI State Machine

```mermaid
stateDiagram-v2
    [*] --> Connecting
    Connecting --> Live: connection established, initial snapshot received
    Connecting --> Reconnecting: connection failed

    state Live {
        [*] --> Idle
        Idle --> AlertFocused: select alert
        AlertFocused --> Idle: Esc
        Idle --> CommandMode: press ':'
        CommandMode --> Idle: executed or Esc
        CommandMode --> ConfirmPending: high-risk command entered
        ConfirmPending --> Idle: confirmed and executed, or cancelled
    }

    Live --> Reconnecting: stream disconnects
    Reconnecting --> Live: reconnect succeeds
    note right of Reconnecting
        retries with backoff,
        fresh snapshot applied
        once reconnected
    end note
    Live --> [*]: 'q' at top level
```

The `Reconnecting` state is rendered distinctly (a visible banner, dimmed data) rather than silently freezing the last-known view — an operator must always be able to tell live data from stale data at a glance.

## 22. MCP Tool Contract Stability & Versioning

> Treat MCP tool definitions as a stable public contract once shipped. An agent workflow built against `apply_intent` breaking silently because an intent's parameters changed shape is a worse failure mode than a CLI flag rename, because there is no human in the loop to notice that the help text changed.

Rules that follow from this:

- Adding an optional field to a tool's or an intent's input schema is non-breaking and may ship in a minor version.
- Removing a field, renaming a field, or changing a field's required-ness is breaking and requires either a new tool/intent name (e.g. `harden-ssh-v2`) or a major version bump of the MCP server's advertised capability set, with the old one kept available and marked deprecated for at least one full release cycle.
- The `kbop://capabilities` and `kbop://intents` resources include a schema version for each entry, so a well-behaved agent client can detect a version it doesn't recognize and degrade gracefully rather than calling blind.

## 23. Tech Stack & Rationale

| Component | Choice | Why |
|---|---|---|
| Local backend daemon | Go | Strong concurrency primitives for the reconciliation loop's per-fabric goroutines plus fan-in from `/proc`/log sources; single static binary output simplifies packaging |
| `ctl` | Go, Cobra | Best-in-class CLI framework ecosystem; shares a language and generated-client code with the backend |
| `tui` | Rust, `ratatui` | Fast, low-resource terminal rendering with a mature immediate-mode-style widget ecosystem; strong async gRPC client support via `tonic` |
| `mcp` | Go or TypeScript, official MCP SDK | Both have mature first-party MCP server SDKs; pick whichever language has the cleaner generated gRPC client bindings available at implementation time |
| Web dashboard | React + TypeScript, D3.js (graph) and Recharts (time series) | Standard, well-supported stack for the visualization-heavy views a terminal can't do well |
| Transport | gRPC over UDS (local, unary + server-streaming); WebSocket gateway for the dashboard | Fast and simply permissioned for same-host callers; no network exposure by default |
| Config format | TOML | More ergonomic than YAML for hand-edited operator config, avoids YAML's well-known parsing footguns; fabric spec documents themselves stay YAML (§8.3) since that's the more natural fit for a desired-state document |
| Embedded SSH service | Go, `golang.org/x/crypto/ssh` | Same language as the backend daemon it's embedded in; well-audited primitive library rather than a bespoke SSH implementation |

## 24. Repository Layout & Build System

```
kb-op/
├── backend/                # backend daemon (Go)
│   ├── cmd/kbopd/           # daemon entrypoint
│   ├── internal/rpc/        # gRPC server, WebSocket gateway
│   ├── internal/authz/      # authorization layer
│   ├── internal/audit/      # audit writer + chain verification
│   ├── internal/capability/ # capability registry + process-action implementations
│   ├── internal/fabric/     # fabric spec types, Provider interface (§8.4)
│   ├── internal/reconcile/  # reconciliation loop
│   ├── internal/provider/   # one package per fabric provider
│   │   ├── systemd/
│   │   ├── openrc/
│   │   ├── hardening/
│   │   ├── patchposture/
│   │   ├── logposture/
│   │   └── scheduledtasks/
│   ├── internal/hoststate/  # /proc poller, journald/auditd tail
│   └── internal/ssh/        # embedded SSH service + PTY spawn
├── proto/                  # .proto service definitions, single source of truth
├── ctl/                    # CLI client (Go, Cobra)
├── tui/                    # terminal console (Rust, ratatui)
├── mcp/                    # MCP server
├── dashboard/               # web dashboard (React + TS)
├── docs/                   # this document and any ADRs
├── scripts/                 # install scripts, dev environment setup
└── tests/                   # integration tests, mock backend fixtures
```

Build orchestration: a top-level `Makefile` (or `Taskfile`) with targets per component (`make backend`, `make ctl`, `make tui`, `make mcp`, `make dashboard`, `make all`), plus a `make proto` target that regenerates all client bindings from `proto/` and fails the build if generated code doesn't match what's committed (catches contract drift at build time, not runtime).

## 25. Configuration Reference

| Key | Component | Default | Description |
|---|---|---|---|
| `backend.socket_path` | backend, all clients | `/run/kb-op/kbopd.sock` | UDS path for the RPC server |
| `backend.log_level` | backend | `info` | `debug`/`info`/`warn`/`error` |
| `backend.proc_poll_interval` | backend | `1s` | `/proc` polling cadence |
| `backend.reconcile_interval` | backend | `30s` | Global default fabric reconciliation cadence; overridable per fabric |
| `backend.fabrics.service_state.enabled` | backend | `true` (if systemd or OpenRC found) | Toggle |
| `backend.fabrics.service_state.provider` | backend | `auto` | `auto`/`systemd`/`openrc` |
| `backend.fabrics.hardening.enabled` | backend | `true` | Toggle |
| `backend.fabrics.patch_posture.provider` | backend | `auto` | `auto`/`apt`/`dnf`/`pkg` |
| `backend.fabrics.log_posture.enabled` | backend | `true` | Toggle |
| `backend.fabrics.scheduled_tasks.enabled` | backend | `true` | Toggle |
| `backend.fabrics.<id>.reconcile_interval` | backend | inherits global | Per-fabric override |
| `audit.log_path` | backend | `/var/log/kb-op/audit.log` | Append-only audit log location |
| `ssh.host_key_path` | backend | `/etc/kb-op/ssh_host_ed25519_key` | Persistent SSH host key |
| `ssh.authorized_keys_path` | backend | `/etc/kb-op/authorized_keys` | Operator public keys |
| `mcp.transport` | mcp | `stdio` | `stdio` or `http-sse` |
| `mcp.http_sse.bind_addr` | mcp | `127.0.0.1:8090` | Only used when transport is `http-sse` |
| `ctl.default_output` | ctl | `table` | `table` or `json` |
| `dashboard.bind_addr` | dashboard | `127.0.0.1:8091` | Dev-server / production bind address |

Configuration is read from a single TOML file (`/etc/kb-op/config.toml`) with environment-variable overrides (`KBOP_<SECTION>_<KEY>`) for containerized or CI deployment convenience.

## 26. Security Model & Threat Model

### 26.1 Privilege model

The backend daemon runs as a dedicated non-root system user. Individual OS capabilities and file-write permissions (e.g. the ability to write `/etc/ssh/sshd_config`, granted only to the hardening provider) are granted narrowly via the packaging's systemd unit, not via running the whole process as root — a bug in the patch-posture provider should not have the ability to rewrite SSH hardening config, and vice versa.

### 26.2 MCP as a potential privilege-escalation shortcut — and its mitigations

The single biggest novel risk this architecture introduces relative to a CLI-only tool is that an LLM agent, potentially acting semi-autonomously and potentially manipulated by adversarial input it's processing (a classic prompt-injection scenario), gets a structured, low-friction way to trigger real actions. Mitigations, several already covered elsewhere and restated here as a consolidated threat-model view:

| Threat | Mitigation | Where specified |
|---|---|---|
| Agent granted broader privilege than a human by default | Agent identity class capped at least-privileged operator role by default; must be explicitly elevated per-deployment | §16.1 |
| Agent bypasses confirmation a human would face | `reason` field required server-side for `high`+ tier regardless of client; risk-tier gating enforced in the backend, not the client | §16.3, §16.2 |
| Agent's write surface is too broad to reason about safely | The primary agent-facing write path is `apply_intent`, a fixed catalog of named, parameter-bounded actions (§18.2) — deliberately narrower than the general `DeclareFabric` capability, which carries a higher default risk tier for exactly this reason | §11.5, §18.2 |
| Prompt-injected instruction causes an unwanted high-risk tool call | Out of scope for kb-op itself to fully solve (this is a property of the calling agent's own defenses) — but kb-op ensures every such call is fully audited with caller identity and reason, and rate limiting below bounds blast radius | §17, §26.3 |
| Stale/incorrect MCP tool contract causes an agent to call something unintended | Tool contract stability rules (Chapter 22) | §22 |
| Compromised MCP transport (networked HTTP+SSE mode) used to impersonate an agent | Scoped bearer tokens, distinct identity class, same authz pipeline as everything else | §16.1 |

### 26.3 Rate limiting on high-risk actions

The backend enforces a configurable rate limit on `high`/`critical` tier capability, fabric-declare, and intent invocations per identity per time window (default: 10 high-risk actions per identity per 5 minutes) — not to prevent a legitimate burst of operator activity during a real incident (the limit is deliberately generous), but to bound the damage of a malfunctioning or manipulated automated caller (an agent stuck in a loop, a buggy script) before a human necessarily notices.

### 26.4 Input validation

All RPC inputs are validated server-side regardless of client-side validation already performed (fabric spec schema validation per fabric type, intent parameter bounds checking, PID existence for process actions) — the backend treats every client, including its own bundled `ctl`, as an untrusted input source at the RPC boundary.

## 27. Performance Engineering

### 27.1 TUI render latency budget

A live TUI that visibly stutters undermines the entire "live operator surface" value proposition. Target budget: input-to-redraw latency under 16ms for any local interaction (selection movement, view switch), and under 100ms from a backend-pushed event (new alert, process change, fabric status change) to that event being reflected on screen, including network/IPC hop over the local UDS.

### 27.2 RPC call budget

Unary RPC calls over local UDS should complete in single-digit milliseconds for `read`-tier capabilities backed by already-cached state (e.g. the last `/proc` poll snapshot, or the last reconciliation tick's fabric status), and under 100ms for `high`-tier capabilities that involve an actual OS-primitive action (e.g. applying a cgroup restriction for a quarantine). Fabric declares themselves return quickly (the RPC just stores the desired state and returns), while the actual convergence happens asynchronously on the reconciliation loop's own schedule (§8.4) — a fabric declare's RPC latency is deliberately decoupled from a fabric provider's potentially slower `Apply()` round-trip, so a caller is never left waiting on a full convergence pass just to know their declaration was accepted.

### 27.3 Process source scaling

The `/proc` poller's cost scales with process count; on a host with several thousand processes, a naive full-rescan-every-tick approach becomes the dominant cost. Mitigation: incremental scanning (only re-read `/proc/[pid]/stat` for PIDs known to have changed since last tick, detected cheaply via `/proc`'s own directory-entry churn) rather than a full stat-everything sweep every second.

## 28. Reliability & Failure Modes

| Failure | Detection | Behavior |
|---|---|---|
| Backend daemon crashes | Client RPC calls fail with `Unavailable` | `ctl` exits with code 3 and a clear message; `tui` enters `Reconnecting` state (Chapter 21), retries with exponential backoff, never silently freezes on stale data |
| Backend daemon restarts (e.g. after an update) | Same as above, followed by successful reconnect | Systemd unit configured with automatic restart; `tui`/`mcp` sessions reconnect and request a fresh full snapshot rather than assuming continuity; the reconciliation loop resumes from persisted desired-state records, not from scratch |
| A fabric provider's underlying mechanism is unavailable (e.g. systemd is not the init system, or a BSD host has no PAM) | Provider selection at startup (§8.5) fails to match | That fabric is marked `unavailable` in `ctl fabric list`; declares against it are rejected with a clear reason, not a hang |
| A fabric provider's `Apply()` call partially converges (some fields succeed, others don't) | Provider returns a partial-success result | The unconverged fields remain visible in `ListFabricDrift` rather than the whole fabric being marked converged; the reconciliation loop retries on its next tick |
| Audit log write fails (disk full, permission issue) | Audit writer returns an error | The triggering capability call **fails closed** — an action whose audit record cannot be written must not be allowed to execute; this is a deliberate trade of availability for guaranteed auditability on the actions that matter most |
| SSH host key file is lost/corrupted | Daemon fails to start SSH service | Daemon logs a clear startup error and continues running its RPC/local-socket surface (local `ctl`/`tui` still work) but does not silently regenerate a new host key, which would break operator trust-on-first-use expectations without an explicit, logged operator action |

## 29. Observability, Logging & Debugging

- **Structured logs**: the backend daemon emits structured (JSON) logs to stdout/systemd-journal, separate from the audit log (Chapter 17) — operational logs are for debugging the daemon itself; the audit log is for reconstructing what actions and corrections were taken and by whom (or by the reconciliation loop itself), and the two must never be merged into one stream or one retention policy.
- **Metrics**: basic operational metrics (RPC call counts/latencies by method, fabric reconciliation duration and drift count per fabric, `/proc` poll duration) exposed on a local-only metrics endpoint in a standard format (Prometheus text exposition), so operators who already run a metrics stack can scrape it without kb-op needing to ship its own dashboard for this purpose.
- **`ctl backend status`**: a single command that surfaces daemon uptime, fabric status table (provider, sync state, last reconciled), current RPC error rate, and audit-chain verification status — the first command to run when something seems wrong.
- **Debug mode**: `--debug` on `ctl`/`tui` enables verbose RPC tracing (request/response payloads, timing) to a local file, off by default given payloads may include sensitive host state.

## 30. Testing Strategy

### 30.1 Mock backend

A lightweight mock implementation of the same `.proto` service, returning canned or seeded-random data, lives in `tests/mockbackend/`. All four client interfaces (`ctl`, `tui`, `mcp`, dashboard) have an integration test suite that runs against this mock backend rather than a real daemon with real providers — this makes CI fast and deterministic, and makes it possible to build/test any one interface without the others.

### 30.2 Per-interface parity tests

A dedicated parity test suite issues the same logical action (e.g. "apply the harden-ssh intent with reason X") through each of `ctl`, a scripted `tui` key-sequence harness, and a direct MCP tool call, against the mock backend, and asserts all three produce an equivalent RPC call with equivalent parameters — this is the automated enforcement of the "one capability, one implementation" principle (Chapter 5), catching drift at CI time rather than in production.

### 30.3 Fabric provider tests

Each fabric provider has its own integration test suite that runs against a real instance of its target mechanism in a disposable container or VM (a real `systemd` PID 1, a real `OpenRC` init, a real `sshd_config` file on disk) — mocking the provider's own target mechanism is explicitly avoided, because the whole value of a provider is correctly observing and converging that mechanism's real state, and a mock of it can silently drift from the real thing exactly the way tool-specific glue code always eventually does. A separate reconciliation-loop test suite verifies convergence, drift detection, and audit-record correctness against a fake `Provider` implementation with injectable `Observe`/`Apply` behavior, so timing- and retry-related logic can be tested without waiting on real system state changes.

### 30.4 Authorization and audit tests

A dedicated suite asserts, for every capability, fabric, and intent in the registry, that: an unauthenticated caller is rejected, an under-privileged caller is rejected, a `high`-tier call without `reason` is rejected, every successful and failed call produces exactly one audit record (and every reconciliation-loop drift correction produces its own, attributed to the `reconciliation-loop` actor per §17.1), and the audit chain remains valid after each test run.

## 31. Deployment & Packaging

- **Single install**: the backend daemon, `ctl`, `tui`, and `mcp` ship as a single package (`.deb`/`.rpm`, or an install script for other distros) installing to standard paths, with a systemd unit for the daemon (`kb-opd.service`) and a `Restart=on-failure` policy.
- **Dashboard**: shipped as a static build served by the backend daemon itself on a local-only port by default (no separate web server dependency), with a documented option to reverse-proxy it behind the operator's own TLS-terminating proxy if remote browser access is desired.
- **Configuration on first install**: an install-time step generates the SSH host key (§13.3), creates the dedicated `kb-op` system user, and writes a starter `config.toml` with auto-detected fabric provider availability (which init system, which package manager, whether PAM is present).
- **Upgrades**: the daemon supports a graceful drain (finish in-flight RPCs, reject new ones with a clear "upgrading" status, let the current reconciliation tick finish) before a systemd-managed restart during an in-place upgrade, so `tui` sessions get a clean `Reconnecting` transition rather than an abrupt disconnect indistinguishable from a crash.

## 32. Operations Runbook

| Situation | First command | Likely next step |
|---|---|---|
| "Is kb-op healthy?" | `ctl backend status` | Check the fabric status table for anything unexpectedly `unavailable` |
| "Is any fabric drifted right now?" | `ctl fabric drift` | Cross-reference the most recent correction attempt in `ctl audit query --capability reconcile --since 1h`; a fabric that keeps re-drifting is worth investigating for an external cause |
| "Did anyone quarantine anything recently?" | `ctl audit query --capability quarantine_process --since 24h` | Cross-reference `audit_id` with `tui`/agent session logs if the actor needs more context |
| "I suspect the audit log was tampered with" | `ctl audit verify` | If chain verification fails, treat as a security incident — this is exactly the scenario the hash chain (§17.2) exists to surface |
| "An operator can't SSH in" | Check `authorized_keys` on the host matches the operator's expected public key | Re-add key, no daemon restart required — the SSH service re-reads the file per connection attempt |
| "TUI shows stale data" | Check for a visible `Reconnecting` banner (§21) | If not visibly reconnecting but data looks stale, this is a bug — file it; the state machine is designed to make this state impossible to hide |
| "An MCP agent took an action I didn't expect" | `ctl audit query --caller mcp --since 1h` | Every MCP-originated action has full audit detail including the reason field the agent supplied — start there |

## 33. Roadmap to v1.0 and Beyond

```mermaid
gantt
    title kb-op roadmap to v1.0 (relative timeline, not calendar-committed dates)
    dateFormat YYYY-MM-DD
    axisFormat %m/%d
    section Phase 0 — Foundation
    Backend /proc read + minimal gRPC read API      :p0, 2025-01-01, 3w
    ctl list/describe against real backend           :p0b, after p0, 2w
    section Phase 1 — First fabric and first action
    service-state fabric via systemd + reconciliation loop :p1, after p0b, 4w
    journald tail as real log source                  :p1b, after p1, 2w
    ctl fabric declare/status + process quarantine/release :p1c, after p1b, 2w
    section Phase 2 — Live surface
    tui live streaming views                          :p2, after p1c, 4w
    SSH-fronted operator access                        :p2b, after p2, 2w
    section Phase 3 — Agent surface
    mcp server, tools, resources, apply_intent          :p3, after p2b, 4w
    remaining fabric providers, hardening, patch, log, cron :p3b, after p3, 4w
    authz/audit parity test suite                       :p3c, after p3b, 2w
    section Phase 4 — v1.0
    web dashboard                                       :p4, after p3c, 4w
    packaging + install script                          :p4b, after p4, 2w
    docs site                                            :p4c, after p4b, 1w
```

### Phase 0 — Foundation
Backend daemon reads `/proc` and exposes a minimal gRPC read API. `ctl list`/`describe` work against the real backend. This alone is a usable, demoable v0.1.

### Phase 1 — First fabric and first action
One real fabric provider (`service-state` via `systemd`) with the reconciliation loop running against it, and one real log source (journald tail). `ctl` gains `fabric declare`/`status` and process `quarantine`/`release` write commands. Authorization and audit logging land here, not later — every write capability from this phase onward is built authorized-and-audited from day one, never retrofitted.

### Phase 2 — Live surface
`tui` with live streaming views against the same backend, including the Fabrics tab. SSH-fronted access becomes the primary remote entry point.

### Phase 3 — Agent surface
`mcp` server exposing the same capabilities as MCP tools/resources, including `apply_intent` against the fixed intent catalog, verified for authz/audit parity against `ctl` via the automated parity suite (§30.2). Remaining fabric providers (`hardening`, `patch-posture`, `log-posture`, `scheduled-tasks`) come online.

### Phase 4 — v1.0
Web dashboard for the visualization-only views. Full packaging (single install, systemd unit, docs site). At this point the product is a complete, standalone, installable operator platform requiring nothing else.

### Beyond v1.0 (explicitly out of scope for this document, noted for completeness)
- Multi-host fleet mode, reusing the same RPC contract with a remote transport.
- A pluggable fabric-provider interface so third parties can add support for additional OS families (further BSD variants, other init systems) without modifying the core daemon.
- Write-once/remote-shipped audit log storage as a stronger tamper-*prevention* (not just detection) guarantee.
- A pluggable, swapped-in backend implementing richer detection/correlation logic behind the same contract (Chapter 19).

## 34. Worked Operator Walkthrough

This chapter narrates one complete, realistic operator session end to end, cross-referencing exactly which RPC calls and chapters cover each step. It exists so a new contributor can read one linear story and see how the pieces in Chapters 7–21 actually compose in practice, rather than only ever seeing them described independently.

### 34.1 Scenario

An operator, `priya`, is paged at 14:20 by an external alerting channel (out of scope for kb-op itself — kb-op is what she uses once she's already been told something is worth looking at) about unusual outbound traffic from `web-03`.

### 34.2 Step by step

**1. Connecting.** Priya runs `ssh kb-op@web-03`. The embedded SSH service (Chapter 13) authenticates her public key against `authorized_keys`, allocates a PTY, and spawns `tui` attached to the session. `tui` opens its long-lived RPC connection to the backend daemon over the local UDS and requests an initial snapshot — the TUI state machine (Chapter 21) moves from `Connecting` to `Live`.

**2. Orientation.** The status bar (§10.1) already shows `⚠ 3 alerts in last 15m`. Priya presses `2` to switch to the Alerts view — a local, already-cached view switch, no RPC call needed, since the alert feed was already streaming in the background per §20.2.

**3. Investigating.** She selects the top alert (severity `HIGH`, `unexpected-setuid` from process 2211) and presses `Enter`, landing on the alert-focused detail view from §10.5. She presses `i` to open the `investigate_process` guided flow (Chapter 36) for pid 2211. Behind the scenes this issues three read-tier RPC calls in sequence — `DescribeProcess(2211)`, `QueryAuditLog(pid=2211, since=15m)`, and a connections lookup — each independently authorized per §16.2 (all `read` tier, so only a valid identity is required, no `reason`).

**4. Corroborating.** The investigation view surfaces that pid 2211 (`python3 worker.py`, normally running as `app`, part of the `worker.service` systemd unit) briefly transitioned to `uid 0` and opened an outbound connection to an address outside the host's normal egress pattern. This matches the paging alert. Priya decides to act.

**5. Acting.** She presses `Esc` to return to the alert-focused view, then `q` to quarantine. Per §10.2's confirmation rule, this does not fire immediately — the TUI's `ConfirmPending` state (Chapter 21) opens a small prompt asking for a `reason` (required at `high` tier per §16.2) and a `y`/`N` confirmation. She types `"uid transition + unexpected egress, pid 2211"` and confirms.

**6. What happens on confirm.** This follows the same pattern as the sequence diagrams in §15: `tui` issues `QuarantineProcess(pid=2211, reason="...")` over gRPC, the backend's authorizer checks Priya's identity and the `high` risk tier requirement, the capability implementation applies the cgroup/network-namespace isolation directly (this is a live OS-primitive action, not a fabric — §8.1), and the audit writer appends a chained record and returns an `audit_id`. `tui` renders `Quarantined pid 2211 (audit: c7e2a1)` in the status line.

**7. Following up.** Priya wants to stop the whole `worker.service` unit from restarting the compromised job while investigation continues, and prevent it from silently starting itself back up (systemd's own restart policy would otherwise do exactly that). She presses `:` and types `intent apply mask-unit --param unit_name=worker.service --reason "compromised pid 2211 was part of this unit, audit c7e2a1" --yes`. Because `mask-unit` is `high` tier, this drops into `ConfirmPending` (already satisfied by `--yes` here since she's typed the full command in one line) before the backend sees the RPC call — it executes the same `ApplyIntent` path shown in §15.2, just from `tui`'s command mode instead of an agent.

**8. Verifying the trail.** Once the incident is stable, she runs (from a separate terminal, using `ctl` directly rather than the TUI's command mode) `ctl audit query --since 30m --caller priya --format json` and confirms both actions — the quarantine and the `mask-unit` intent application — are present, correctly chained, with matching `audit_id`s and legible `reason` fields — exactly the query pattern described in the runbook (Chapter 32).

### 34.3 What this walkthrough demonstrates

- Every action Priya took — whether through a keybinding, the TUI's command mode, or a separate `ctl` invocation — passed through the identical authorization and audit path described in Chapters 16–17. Nothing about *how* she issued a command changed *what* was enforced or logged.
- The quarantine action (a direct OS primitive) and the `mask-unit` intent application (a fabric-adjacent, templated write) are both fully audited and both terminal-first, even though they're structurally different kinds of capability — confirming that the "one capability, one implementation" principle holds across both categories, not just within one.
- The guided investigation flow (`investigate_process`) is the same MCP prompt template an LLM agent would use (Chapter 36), just rendered inside the TUI instead of an agent's chat surface — confirming the reuse claim made in §10.5.
- No step required leaving the terminal, per the terminal-first principle (Chapter 5).

## 35. Troubleshooting & FAQ

This chapter collects the failure reports a new deployment is most likely to generate in its first weeks, organized by symptom.

### 35.1 "The backend daemon won't start"

| Check | Command | Likely cause |
|---|---|---|
| Is the socket path writable? | `ls -la /run/kb-op/` | `kb-op` system user lacks permission on `/run/kb-op/`; re-run the install script's user/permission step |
| Are required capabilities granted? | `systemctl show kb-opd -p AmbientCapabilities` | A fabric provider needing elevated file-write permission (e.g. the hardening provider writing `/etc/ssh/sshd_config`) is enabled but the systemd unit wasn't regenerated after enabling it — re-run `make install-unit` or the packaged equivalent |
| Is the config file valid TOML? | `kb-opd --check-config` | A hand-edited `config.toml` has a syntax error; the daemon intentionally refuses to start on invalid config rather than falling back to defaults silently |
| Is another process already bound to the socket path? | `ss -lx \| grep kbopd.sock` | A previous crashed instance left a stale socket file; remove it only after confirming via `ps` that no `kbopd` process is actually running |

### 35.2 "`tui` connects but shows no data" / "`tui` can't connect at all"

- First check `ctl backend status` from a separate session — if that also fails, the problem is the backend, not the TUI (see 35.1).
- If `ctl backend status` succeeds but `tui` still shows nothing, confirm the TUI is pointed at the same socket path as `ctl` (`KBOP_BACKEND_SOCKET_PATH` env var or `backend.socket_path` in config, §25) — a common first-deployment mistake is a stale path left over from a manual test run.
- If `tui` shows a persistent `Reconnecting` banner (§21) rather than silence, that is the system working correctly and telling you exactly what's wrong — it is never a bug in itself; treat it as a backend-availability problem per 35.1.

### 35.3 "MCP tool calls return permission-denied"

- Confirm the calling identity's role. Per §16.1, an `mcp` caller (local stdio or networked HTTP+SSE) is mapped to an identity the same way any other caller is — a permission-denied on a `high`-tier tool most often means the agent identity class hasn't been granted the operator role for that capability, which is the correct default-deny behavior, not a bug (§26.2).
- Confirm the tool call included a non-empty `reason` field for `high`+ tier tools or intents — the backend rejects these server-side per §16.3 regardless of what the MCP schema's `required` array says client-side, so a client that skips schema validation will still be correctly rejected.
- Use `kbop://capabilities` and `kbop://intents` (resources, not tool calls) to have the agent itself check what it can actually do and declare on this host before attempting an action — this sidesteps a whole class of "why did this fail" confusion by making availability and permission self-discoverable (§8.5).

### 35.4 "SSH access isn't working for a new operator"

- Confirm the operator's public key is present, on its own line, in `ssh.authorized_keys_path` (§25) — the SSH service re-reads this file per connection attempt, so no daemon restart is required after adding a key, and a restart is never the fix here.
- Confirm the key type is one the embedded SSH service accepts (Ed25519 or RSA ≥ 3072-bit by default; weaker key types are intentionally rejected, not silently downgraded).
- If the connection is refused before authentication is even attempted, confirm the host's normal SSH daemon (if any) isn't competing for the same port — kb-op's embedded SSH service is typically deployed on a distinct port from any pre-existing OpenSSH server on the box, documented per-deployment in the install notes.

### 35.5 "A fabric shows `unavailable` but the underlying mechanism is definitely present"

- Re-check the provider's expected binary/API path against the host's actual configuration (§25's `backend.fabrics.*.provider` keys) — a non-default init system layout or an unusual `apt`/`dnf` alias is the most common cause.
- Check `ctl backend status` for the fabric's last provider-selection error message — this is surfaced verbatim from the provider probe (§8.5) rather than a generic "unavailable," specifically so this class of problem is diagnosable from one command.
- If the host genuinely uses an init system or package manager with no shipped provider (an uncommon BSD variant, for instance), that fabric is correctly `unavailable` — see the "Beyond v1.0" pluggable-provider extension point (Chapter 33) rather than treating this as a bug to work around today.

### 35.6 "The audit chain failed verification"

Per §17.2, this is treated as a security incident, not a bug report to quietly work around. Do not attempt to "repair" the chain by regenerating it. The runbook (Chapter 32) is the correct next step: stop routine operations against the affected host's audit trail, preserve the log file as-is for investigation, and escalate.

### 35.7 "A fabric keeps drifting back to the same wrong state"

- This is exactly the signal the `reconciliation-loop`-attributed audit records (§17.1) exist to surface — run `ctl audit query --capability reconcile --fabric <id> --since 7d` and look for a repeating pattern.
- The most common cause is something outside kb-op's control actively reasserting the old state on a schedule of its own — a separate configuration-management tool that doesn't know about kb-op's declared fabric, or a package upgrade's post-install script resetting a config file kb-op is also managing. The fix is organizational (stop the other tool from touching that file, or bring its behavior into the fabric's own desired state) rather than anything kb-op itself needs to change.

## 36. MCP Prompt Template Reference

Prompt templates (Chapter 11's third MCP primitive) bundle several resource reads and, where appropriate, a suggested tool call into one named, reusable workflow that an agent or IDE surfaces to its user rather than requiring the user to know which raw tools/resources to chain together manually. This chapter specifies the templates kb-op ships with in v1.0.

### 36.1 `investigate_process`

Already introduced in §11.4; full specification:

```json
{
  "name": "investigate_process",
  "description": "Guided investigation of a specific process: pulls process detail, recent related audit events, and open network connections, then suggests next steps such as quarantine if warranted.",
  "arguments": [
    { "name": "pid", "description": "Process ID to investigate", "required": true }
  ]
}
```

**Template text** (rendered with `{{pid}}` substituted):

> Investigate process `{{pid}}` on this host. Call `describe_process` for `{{pid}}`, then `kbop://audit/recent` filtered to this pid over the last 15 minutes, then check for open network connections associated with this pid. Summarize: what is this process, has its privilege or network behavior changed recently, and does anything here warrant a `quarantine_process` call. If you recommend quarantine, state the exact `reason` text you would use.

This is the same flow the TUI's `i` binding drives internally (§10.5) — the template text above is effectively the specification the TUI's built-in equivalent is implemented against, kept in this document as the single source of truth for both.

### 36.2 `triage_alert`

```json
{
  "name": "triage_alert",
  "description": "Given a specific alert ID, gather its full context and produce a structured triage summary with a recommended severity and next action.",
  "arguments": [
    { "name": "alert_id", "description": "Alert identifier from the alert feed", "required": true }
  ]
}
```

**Template text:**

> Triage alert `{{alert_id}}`. Read its full record via `kbop://alerts/recent`, identify the associated process if any, and use `investigate_process` as appropriate to gather corroborating context. Produce: (1) a one-sentence summary, (2) confirmed severity (agree or disagree with the alert's own severity field, with reasoning), (3) a recommended next action — no action, monitor, or a specific `high`-tier tool call (or templated intent) with the exact `reason` text you would use if a human approves it. Do not call any `high`-tier tool or intent yourself as part of this template — recommend it and stop.

> **Design rationale:** this template deliberately stops short of taking action itself, even though the underlying tools would technically allow it. A triage template's job is to compress investigation time for whoever — human or a more autonomous downstream agent — makes the actual call; baking an automatic action into a template used for many different alerts, under many different deployment risk tolerances, would quietly reintroduce exactly the "did the agent get a shortcut around a human decision" risk Chapter 26 works to close off everywhere else.

### 36.3 `summarize_threat_posture`

```json
{
  "name": "summarize_threat_posture",
  "description": "Produce a current-state summary of this host's security posture: active alerts, fabric sync status and drift, and process anomalies.",
  "arguments": []
}
```

**Template text:**

> Summarize the current security posture of this host. Read `kbop://status`, `kbop://alerts/recent`, and `kbop://fabrics`. Produce a short-form report: overall health (green/yellow/red, with reasoning), count and severity breakdown of recent alerts, which fabrics (if any) currently show drift and how long they've been drifted, and any fabric reporting `unavailable` (§8.5) which would mean this summary itself is incomplete for that domain.

This template is the natural first thing an operator (or an on-call escalation bot ahead of paging a human) runs at the start of a session — it takes no arguments and touches only `read`-tier resources, so it is safe to run with no elevated agent identity at all.

### 36.4 `explain_recent_action`

```json
{
  "name": "explain_recent_action",
  "description": "Given an audit_id, explain what action was taken, by whom (or by the reconciliation loop), why, and whether it is still in effect.",
  "arguments": [
    { "name": "audit_id", "description": "Audit record identifier, as returned by any mutating tool call or shown in ctl/tui output", "required": true }
  ]
}
```

**Template text:**

> Explain audit record `{{audit_id}}`. Read it via `kbop://audit/recent` (filtered/looked up by ID) and produce a plain-language explanation: what capability, fabric declare, or intent was invoked, by which caller identity (a human operator, an agent, or the `reconciliation-loop` itself), with what stated reason, and what the current live state implies about whether the effect is still active — cross-reference the relevant `read`-tier resource (`describe_process`, `kbop://fabrics/{id}/drift`) to answer that last part rather than assuming the original action is still in effect.

This template exists specifically to make the audit log (Chapter 17) useful to more than just the operator who wrote a given `reason` field — a different operator, days later, handed only an `audit_id`, should be able to reconstruct full context without archaeology.

### 36.5 `review_fabric_drift`

```json
{
  "name": "review_fabric_drift",
  "description": "Given a fabric ID, summarize its current drift, how long it has persisted, and whether the pattern suggests something outside kb-op is fighting the declared state.",
  "arguments": [
    { "name": "fabric_id", "description": "Fabric to review, e.g. 'hardening'", "required": true }
  ]
}
```

**Template text:**

> Review drift for fabric `{{fabric_id}}`. Read `kbop://fabrics/{{fabric_id}}/drift` for the current field-by-field diff, then `kbop://audit/recent` filtered to this fabric's reconciliation records over the last 7 days. Summarize: which fields are currently drifted, how many times has the reconciliation loop had to re-correct the same field recently (per 35.7, a repeating pattern suggests an external cause worth investigating), and would applying one of the fixed intents from `kbop://intents` address this drift directly rather than requiring a full `declare_fabric` call. Do not call `apply_intent` or `declare_fabric` yourself — recommend the specific one and stop, per the same rule as `triage_alert`.

This template is the fabric-specific counterpart to `triage_alert` — same "recommend, don't act" discipline, applied to the reconciliation model's own failure signature rather than to a one-shot alert.

## Appendix A: Full `ctl` Command Reference

This appendix expands every row of the Capability Catalog (Chapter 18) into a concrete invocation with example output. It is generated from the same capability registry described in §8.2 — in the real repository this appendix should be produced by a doc-generation step reading the registry directly, so it cannot silently drift from what the backend actually implements; the content below is what that generator would currently produce.

### A.1 `read`-tier commands

```
$ ctl process list --json
[
  {"pid": 1044, "user": "www-data", "cpu_pct": 2.1, "mem_pct": 0.8, "state": "running", "command": "nginx: worker process"},
  {"pid": 1102, "user": "root",     "cpu_pct": 0.0, "mem_pct": 0.3, "state": "running", "command": "sshd: operator [priv]"}
]

$ ctl process describe 2211 --json
{"pid": 2211, "user": "app", "ppid": 1, "started": "2026-07-30T13:58:02Z",
 "command": "python3 worker.py", "cgroup": "/system.slice/worker.service",
 "open_connections": 3, "recent_uid_transitions": []}

$ ctl fabric list --json
[{"fabric": "service-state", "provider": "systemd", "sync": "in-sync", "last_reconciled": "2026-07-30T14:29:58Z"},
 {"fabric": "hardening", "provider": "linux-hardening", "sync": "drifted", "drift_count": 1},
 {"fabric": "patch-posture", "provider": "apt", "sync": "in-sync"},
 {"fabric": "log-posture", "provider": "journald", "sync": "in-sync"},
 {"fabric": "scheduled-tasks", "provider": "cron", "sync": "in-sync"}]

$ ctl fabric drift hardening --json
[{"field": "ssh.password_authentication", "desired": "false", "actual": "true", "severity": "high"}]

$ ctl intent list --json
[{"name": "harden-ssh", "tier": "high", "fabric": "hardening"},
 {"name": "mask-unit", "tier": "high", "fabric": "service-state"},
 {"name": "enforce-auto-updates", "tier": "medium", "fabric": "patch-posture"}]

$ ctl audit query --since 1h --severity high --json
[{"audit_id": "c7e2a1", "capability": "quarantine_process", "caller": "priya",
  "reason": "uid transition + unexpected egress, pid 2211", "result": "success",
  "timestamp": "2026-07-30T14:24:11Z"}]

$ ctl audit export --format json --out audit-2026-07-30.json
wrote 412 records (chain verified) to audit-2026-07-30.json

$ ctl audit verify
chain OK: 4,118 records, no gaps detected

$ ctl capability list --json
[{"name": "quarantine_process", "tier": "high", "available": true},
 {"name": "declare_fabric", "tier": "varies-by-fabric", "available": true},
 {"name": "apply_intent", "tier": "varies-by-intent", "available": true}]

$ ctl backend status
uptime: 4d 02h   fabrics: service-state(ok) hardening(drifted) patch-posture(ok) log-posture(ok) scheduled-tasks(ok)
rpc error rate (5m): 0.0%   audit chain: verified 00:02:14 ago
```

### A.2 `low`/`medium`-tier commands

```
$ ctl fabric declare patch-posture -f patch-posture.yaml --dry-run
would change: patch_posture.auto_security_updates: false -> true (no changes applied)

$ ctl fabric declare patch-posture -f patch-posture.yaml
Fabric 'patch-posture' declared (audit: b2f901), reconciling...

$ ctl intent apply enforce-auto-updates --param enabled=true --param security_only=true
Applied intent 'enforce-auto-updates' (audit: b2fa12)
```

### A.3 `high`-tier commands

```
$ ctl process quarantine 2211 --reason "uid transition + unexpected egress, pid 2211"
Quarantine pid 2211? [y/N] y
Quarantined pid 2211 (audit: c7e2a1)

$ ctl process release 2211 --reason "confirmed benign after investigation, ticket OPS-4471"
Released pid 2211 (audit: c7e2a4)

$ ctl fabric declare hardening -f ssh-hardening.yaml --reason "CIS baseline enforcement"
Declare fabric 'hardening'? [y/N] y
Fabric 'hardening' declared (audit: c7e2b0), reconciling...

$ ctl intent apply mask-unit --param unit_name=worker.service --reason "compromised pid 2211 was part of this unit, audit c7e2a1"
Apply intent 'mask-unit'? [y/N] y
Applied intent 'mask-unit' (audit: c7e2c9)
```

Every `high`-tier example above includes `--reason` inline, matching the client-side fast-fail rule in §9.2 — omitting it produces a `4` exit code and an error before any RPC call is attempted, saving a round trip for the most common scripting mistake.

## Appendix B: Full MCP Tool Reference

This appendix lists every mutating capability's complete MCP tool definition. `quarantine_process` is specified fully in §11.2 and is not repeated verbatim here; its entry below shows only the fields that differ in kind from what's already shown there, for a mutating tool at the same risk tier.

### B.1 `release_process`

```json
{
  "name": "release_process",
  "description": "Release a previously quarantined process, restoring its normal execution and network access. Requires a reason. Subject to the same authorization and audit as ctl process release.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "pid": { "type": "integer", "description": "Process ID to release" },
      "reason": { "type": "string", "description": "Human-readable justification, required" }
    },
    "required": ["pid", "reason"]
  }
}
```
Example call: `{"pid": 2211, "reason": "confirmed benign after investigation, ticket OPS-4471"}`
Example response: `{"success": true, "message": "Released pid 2211", "audit_id": "c7e2a4"}`

### B.2 `declare_fabric`

```json
{
  "name": "declare_fabric",
  "description": "Declare a full desired-state document for one fabric. Higher default risk tier than any single templated intent, because a full desired-state document is a much larger action space than one bounded, named change. Requires a reason for fabrics at high tier (currently: hardening).",
  "inputSchema": {
    "type": "object",
    "properties": {
      "fabric_id": { "type": "string", "description": "One of: service-state, hardening, patch-posture, log-posture, scheduled-tasks" },
      "desired_state": { "type": "string", "description": "YAML desired-state document matching the fabric's spec schema" },
      "reason": { "type": "string", "description": "Human-readable justification, required for high-tier fabrics" }
    },
    "required": ["fabric_id", "desired_state"]
  }
}
```
Example call: `{"fabric_id": "patch-posture", "desired_state": "fabric: patch-posture\nversion: 1\nspec:\n  auto_security_updates: true\n"}`
Example response: `{"success": true, "message": "Fabric 'patch-posture' declared, reconciling", "audit_id": "b2f901"}`

### B.3 `apply_intent`

```json
{
  "name": "apply_intent",
  "description": "Apply one templated, parameter-bounded intent from the fixed catalog (see kbop://intents). This is the preferred write path for autonomous or semi-autonomous agents, since its action space is much smaller and more predictable than declare_fabric. Requires a reason for high-tier intents.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "name": { "type": "string", "description": "Intent name, e.g. 'harden-ssh', 'mask-unit', 'enforce-auto-updates'" },
      "params": { "type": "object", "description": "Parameters matching the named intent's schema, from kbop://intents" },
      "reason": { "type": "string", "description": "Human-readable justification, required for high-tier intents" }
    },
    "required": ["name", "params"]
  }
}
```
Example call: `{"name": "mask-unit", "params": {"unit_name": "worker.service"}, "reason": "compromised pid 2211 was part of this unit, audit c7e2a1"}`
Example response: `{"success": true, "message": "Applied intent 'mask-unit'", "audit_id": "c7e2c9"}`

### B.4 `force_reconcile`

```json
{
  "name": "force_reconcile",
  "description": "Trigger an immediate reconciliation tick for one fabric (or all fabrics if omitted), without waiting for its next scheduled interval. Low risk — this only causes existing declared state to be re-asserted sooner, it cannot introduce a new desired state.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "fabric_id": { "type": "string", "description": "Optional. If omitted, all enabled fabrics are reconciled immediately." }
    },
    "required": []
  }
}
```
Example call: `{"fabric_id": "hardening"}`
Example response: `{"success": true, "message": "Reconciliation triggered for 'hardening'", "audit_id": "d1a002"}`

### B.5 Schema-shape consistency note

> Every tool in this appendix follows the same shape: an `inputSchema` whose `required` array always includes `reason` for any tool whose underlying capability, fabric, or intent is `high` tier or above, a response that always includes `audit_id`, and a `description` field that states the risk framing in plain language rather than leaving an agent to infer it. This consistency is enforced by the same doc/schema generation step that produces Appendix A from the capability registry (§8.2) — an engineer adding a new `high`-tier intent without a `reason` field in its schema should get a build-time failure, not a runtime surprise for whichever agent calls it first.
