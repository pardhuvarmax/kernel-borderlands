# KB AADS — Agent-Assisted Decision System

Multi-agent swarm that interprets KB behavioral signals
and coordinates threat response.

## Structure
- `agents/`    — Individual agent implementations
- `swarm/`     — Swarm orchestration and management
- `consensus/` — Quorum and voting system
- `marl/`      — Multi-agent reinforcement learning
- `comms/`     — gRPC (UDS) client to kb-control-plane; inter-agent messaging is native Ray actor calls, not a separate message bus. Ray itself runs in local (single-node) mode in dev — no network surface; see [`docs/development/control-aads/ray-shared-mutable-state.md`](../docs/development/control-aads/ray-shared-mutable-state.md)'s clarification note.
- `tests/`     — Tests

## Agent Roles
- Patroller   — Baseline monitoring
- Hunter      — Threat investigation
- Healer      — False positive suppression
- Containment — Enforcement coordination
- Idle        — Reserve pool

## Run
```bash
source venv/bin/activate
python main.py
```

## Owner
- Karthik — AI & Agentic Systems,
- Pardhu Varma — ML & Systems (Collab)

