# Communication Layer

Inter-agent and KB↔AADS communication infrastructure.

## Protocols
- Kafka    — Event bus (role-changes, agent-updates, consensus-events)
- ZeroMQ   — Direct agent-to-agent messaging
- gRPC     — KB Control Plane ↔ AADS

## Kafka Topics
- `kb-events`        — Raw events from KB control plane
- `role-changes`     — Agent role transitions
- `agent-updates`    — Agent state updates
- `consensus-events` — Voting events
- `health-checks`    — Agent heartbeats
- `anomaly-alerts`   — Threat alerts
