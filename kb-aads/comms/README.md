# Communication Layer

Inter-agent and KB↔AADS communication infrastructure.

**Corrected — this doc was stale.** It described a ZeroMQ pub/sub design (below,
struck through) from before the Ray-only pivot away from ZeroMQ documented in
`docs/development/control-aads/aads-intelligence-roadmap.md` §"The architecture is
documented — these docs were stale, now fixed". This file had exactly one commit since
project init and was never updated when that pivot happened, same pattern already
caught and fixed for `kb-aads/marl/README.md` and `scripts/dataset/README.md` in that
pass — this one was missed. No `import zmq` exists anywhere in `kb-aads` source
(confirmed via grep); the installed `pyzmq` package in `venv/` is an unused leftover.

## Protocols (as actually implemented)
- Ray IPC — actor remote methods (`swarm/orchestrator.py`'s `RaySwarmOrchestrator`
  spawns/drives all agents via `ray.remote`/`.remote()` calls) and consensus routing
  (`consensus/jje.py`).
- gRPC — AADS → KB Control Plane, `comms/grpc_client.py`'s `ControlPlaneClient`.
  `submit_decision` is live (called from `agents/executor.py`'s `ExecutorAgent`,
  reachable via `swarm/orchestrator.py` → `main.py`). `stream_events`/`stream_alerts`
  are written but have no live caller — see the gap below.

## Known gap: no live path for kb-events reaching the swarm
Confirmed via grep — no agent (`hunter.py`, `base_agent.py`, `patroller.py`, etc.)
references `stream_events`, `ControlPlaneClient`, or any event type. Nothing currently
ingests KB control-plane telemetry into the swarm through any mechanism — not the
ZeroMQ design below (never built), not gRPC streaming (written, uncalled), not Ray.
This is a real open gap, not just a stale-doc problem — flagging it here rather than
implying it's solved by whichever technology replaced ZeroMQ in the pivot.

## ~~ZeroMQ Pub/Sub Channels~~ (never built past this doc — do not treat as implemented)
- ~~`kb-events`~~        — Raw events from KB control plane
- ~~`role-changes`~~     — Agent role transitions
- ~~`agent-updates`~~    — Agent state updates
- ~~`consensus-events`~~ — Voting events
- ~~`health-checks`~~    — Agent heartbeats
- ~~`anomaly-alerts`~~   — Threat alerts
