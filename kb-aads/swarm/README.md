# Swarm Orchestration

Manages the agent swarm lifecycle:
- Agent creation and termination
- Role assignment and rebalancing
- Health monitoring
- Rogue agent detection
- Pheromone trail coordination (stigmergy)

## Key Classes
- `SwarmOrchestrator` — Top-level swarm manager
- `RoleManager`       — Dynamic role assignment
- `HealthMonitor`     — Agent health tracking
- `RogueDetector`     — Anomalous agent detection
