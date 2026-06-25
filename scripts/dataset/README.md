# Dataset Generation Tools

Tools for collecting, labeling, and formatting the KB behavioral dataset.

## Pipeline
1. `collect.py`   — Capture eBPF events during attack simulations
2. `label.py`     — Label events (attack/benign, attack category)
3. `format.py`    — Convert to training format (prompt/completion pairs)
4. `validate.py`  — Validate dataset quality and coverage
5. `split.py`     — Train/validation/test split

## Output Format
```json
{
  "prompt": "Process bash (PID 5678) executed: socket→connect(4444)→dup2→execve(/bin/sh). Score: 79.4. Zone: BORDERLANDS. What is the threat assessment?",
  "completion": "This is a high-confidence reverse shell attack (0.94). The sequence socket→connect on non-standard port→stdio redirect→shell spawn matches IOC pattern REVERSE_SHELL_001. Recommend immediate namespace isolation and quorum vote for termination."
}
```
