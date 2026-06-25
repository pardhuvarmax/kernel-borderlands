# Agent Implementations

Individual agent role implementations.

## Files
- `base_agent.py`      — Abstract base class for all agents
- `hunter.py`          — Threat investigation agent
- `healer.py`          — False positive suppression agent
- `patroller.py`       — Baseline monitoring agent
- `containment.py`     — Enforcement coordination agent
- `idle.py`            — Reserve/standby agent

## Agent Lifecycle
NEW → PROFILING → BASELINE → MONITOR → CONTAINED → TERMINATED
