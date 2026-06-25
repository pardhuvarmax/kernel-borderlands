# KB AADS — Agent-Assisted Decision System

Multi-agent swarm that interprets KB behavioral signals
and coordinates threat response.

## Structure
- `agents/`    — Individual agent implementations
- `swarm/`     — Swarm orchestration and management
- `consensus/` — Quorum and voting system
- `marl/`      — Multi-agent reinforcement learning
- `comms/`     — Kafka/ZeroMQ communication layer
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
Tejaswini — Backend/Communication (collab)
