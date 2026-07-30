# Emergency Backup — Independent Project Docs

**Status:** Contingency planning document
**Date:** 2026-07-30
**Purpose:** In the event our club/team is disbanded or restructured due to ongoing authoritative/governance tensions, this directory preserves full, standalone end-to-end project documentation so each contributor can walk away with their own complete product — not a fragment that needs the others to make sense.

## Why this exists

The original project (`kernel-borderlands`) was organized as one platform made of subsystems, each led by a different contributor. If the team is forced to split, ownership tensions or losing access to a shared repo/org should not mean any single person loses the ability to continue their piece as a real project. So each doc below is **not** "the subsystem's architecture within the bigger platform" — it is written as if that piece is the *entire* product: its own vision, its own problem statement, its own architecture that owns its inputs and outputs (no assuming some other team's service exists), its own tech stack, and its own roadmap to a v1.0 that ships and is useful on its own.

They can still interoperate if the team stays together (loosely noted per-doc where relevant), but that is a bonus, not the premise. Read any one of these on its own and you have everything needed to start building it cold in a brand-new repo.

## The four projects

| Codename | Owner track | One-liner |
|---|---|---|
| [kb-core](./kb-core.md) | Kernel/eBPF | A complete eBPF-based kernel security product for Linux servers — kernel-level visibility and in-kernel enforcement, ships as one binary |
| [kb-cp](./kb-cp.md) | Systems integration | A complete adapter/porting product that unifies established security tools (nftables, fail2ban, auditd, ClamAV, Suricata, AppArmor/SELinux) behind one fast protocol |
| [kb-aads](./kb-aads.md) | Distributed systems/Agents | A complete agentic security swarm — its own telemetry input, its own decision-making, its own enforcement connectors |
| [kb-op](./kb-op.md) | DX/Interfaces | A complete unified interface product — CLI (`ctl`), TUI, MCP server, all backed by its own built-in local backend daemon |

## How to use this backup

1. Each `.md` file is fully self-contained — read and build from it without needing any of the others.
2. If forking, copy the relevant doc into the new repo's `docs/ARCHITECTURE.md` (or `VISION.md`) and treat it as the north star through v1.0.
3. Update the "Owner track" column above if reassigned.
4. This is architecture-level documentation, not code — it defines vision, problem statement, module design, tech stack, and a phased roadmap so implementation can start cold in a brand-new repo with no other context required.
