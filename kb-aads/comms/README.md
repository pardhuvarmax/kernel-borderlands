# Communication Layer

Inter-agent and KB↔AADS communication infrastructure.

## Protocols
- ZeroMQ   — Event bus & direct agent-to-agent messaging (pub/sub topics)
- Ray IPC  — High-performance actor remote methods and shared-memory channels
- gRPC     — KB Control Plane ↔ AADS

## ZeroMQ Pub/Sub Channels
- `kb-events`        — Raw events from KB control plane
- `role-changes`     — Agent role transitions
- `agent-updates`    — Agent state updates
- `consensus-events` — Voting events
- `health-checks`    — Agent heartbeats
- `anomaly-alerts`   — Threat alerts
