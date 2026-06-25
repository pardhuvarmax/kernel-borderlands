# Consensus & Quorum System

Weighted voting for critical swarm decisions.

## Decisions Requiring Consensus
- Process termination
- Agent termination (rogue management)
- Threat level escalation
- Role redistribution
- Emergency mode activation

## Voting Model
- Each agent has a weight based on role and confidence history
- Decisions require M-of-N weighted vote to pass
- Timeout: unresolved votes expire after configurable window
- Results logged to immutable audit trail
