# Dataset Generation Tools

Tools for collecting, labeling, and formatting the KB behavioral dataset. See [`docs/development/control-aads/aads-intelligence-roadmap.md`](../../docs/development/control-aads/aads-intelligence-roadmap.md) Phase 0 for the full, maintained design — this file is a quick-reference summary; if the two disagree, the roadmap doc is newer and wins.

None of the scripts below exist yet (`collect.py`/`label.py`/`format.py`/`validate.py`/`split.py`) — this is a plan, not a built pipeline.

## Pipeline
1. `collect.py`   — Capture eBPF events during attack-lab simulations (`scripts/attack-lab/`), including the six attack scenarios, a benign baseline, and a simulated-rogue-agent scenario category (for calibrating JJE's sub-agent severity scoring — see roadmap's "Severity thresholds" section).
2. `label.py`     — Label events (attack/benign, attack category; sub-agent behavior severity for the rogue-agent scenarios).
3. `format.py`    — Convert to **two** training formats, not one (see "Output Formats" below) — RL-episode-shaped for Jury/Healer/Containment, and agentic-trajectory-shaped for Hunter. These are materially different shapes for different consumers; a single flat format doesn't serve both.
4. `validate.py`  — Validate dataset quality and coverage.
5. `split.py`     — Train/validation/test split.

## Output Formats

### RL-episode format (Jury, Healer, Containment)

State/action/reward sequences matching `kb-aads/marl/env.py`'s `AADSEnv` observation space (built from real `ProcessState`/`KBEvent` wire fields, not placeholder values) and `marl/README.md`'s reward table (TP +1.0 / FP −0.5 / TN +0.1 / FN −1.0). Multi-step, not single-step — real investigation/consensus spans multiple ticks of evolving process state.

### Agentic trajectory format (Hunter)

**Not** flat prompt/completion pairs — Hunter runs a multi-step tool-call loop (see `marl/README.md`), so training data needs to show that process, not just a final answer. Each example is a sequence of turns ending in a final assessment:

```json
{
  "trajectory": [
    {"role": "user", "content": "Investigate PID 5678 (comm: bash) — Patroller flagged a zone transition to BORDERLANDS, score 79.4."},
    {"role": "assistant", "content": "Checking process history before assessing.", "tool_calls": [{"name": "get_process_state", "arguments": {"pid": 5678}}]},
    {"role": "tool", "name": "get_process_state", "content": "{\"pid\": 5678, \"ppid\": 1234, \"comm\": \"bash\", \"score\": 79.4, \"zone\": \"BORDERLANDS\", \"uid\": 1000, \"containment\": \"NONE\", \"first_seen\": ..., \"last_seen\": ...}"},
    {"role": "assistant", "content": "Process shows socket→connect(4444)→dup2→execve(/bin/sh) — high-confidence reverse shell (0.94), matches IOC pattern REVERSE_SHELL_001. Recommend immediate namespace isolation and quorum vote for termination.", "tool_calls": []}
  ]
}
```

Tool calls must match the real schemas derivable from `kb-control-plane/proto/kb.proto` (`PidRequest`, `ZoneRequest`, `EventFilter`) and the four `ControlPlaneClient` methods (`get_process_state`, `list_zone`, `stream_events`, `stream_alerts`) — not free-text tool syntax. Trajectories should include realistic intermediate steps (a tool call that returns unremarkable data, a follow-up call), not just the single-tool-call happy path shown above — Hunter's real iteration cap is 5 calls, so training data should exercise multi-call investigations, not exclusively one-call ones.

**Not yet designed**: exactly how many tool calls per trajectory is "realistic" across the six attack scenarios, and whether some fraction of trajectories should deliberately model the cap-out/forced-conclusion fallback path (roadmap Phase 4) so the model has seen that pattern during training too.
