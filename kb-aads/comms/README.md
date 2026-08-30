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
  do now have one live caller — see the correction below — but not through the
  swarm's intended agent pipeline.

## Known gap: no *production* path for kb-events reaching the swarm

**Correction**: this section previously said "nothing currently ingests KB
control-plane telemetry into the swarm through any mechanism," full stop —
that's no longer literally true. `kb-aads/demo/live_containment_monitor.py`
(a demo driver, not part of the committed agent pipeline) does call
`stream_client.stream_events()` and feed each event straight into a single
persistent `ContainmentAgent` via `receive_message.remote()`. The script's
own docstring is explicit that this is a deliberate bypass for a live demo,
not the real pipeline: it calls Containment directly on *every* event with
no Patroller/Hunter scoring or Judge/Jury consensus gating it, and it
defaults `event_type` to 0 for everything because there's no built mapping
from kb-core's real `KBEvent.event_type` string taxonomy to the 6 category
codes Containment's policy was actually trained on
(`scripts/dataset/label.py`'s `KB_SCENARIO_EVENT_TYPE`).

So: the underlying gap is still real and still open — no agent in the
*designed* pipeline (`hunter.py`, `base_agent.py`, `patroller.py`, etc.)
references `stream_events`/`ControlPlaneClient`, `Patroller` still doesn't
score real telemetry, and the event-type taxonomy mapping doesn't exist.
What's changed is only that "zero callers of any kind" is no longer
accurate — a demo-only bypass exists and works, the production ingestion
path through Patroller still doesn't.

## ~~ZeroMQ Pub/Sub Channels~~ (never built past this doc — do not treat as implemented)
- ~~`kb-events`~~        — Raw events from KB control plane
- ~~`role-changes`~~     — Agent role transitions
- ~~`agent-updates`~~    — Agent state updates
- ~~`consensus-events`~~ — Voting events
- ~~`health-checks`~~    — Agent heartbeats
- ~~`anomaly-alerts`~~   — Threat alerts
