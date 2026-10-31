# Attack Lab

Scenario runner that produces the **labelled, sensor-derived corpus** the learned
policies and every evaluation depend on (plan: `docs/development/control-aads/learned-policy-retraining.md`).

> **Run only on an isolated lab VM.** It performs simulated attack *behaviour* (credential
> reads, privilege transitions, cross-process memory writes, beaconing, RWX memory). All
> network targets are loopback (`127.0.0.0/8`, enforced and tested); all files it creates
> live in a per-run scratch directory; there is no exploit code. `runner.py` will not start
> without `--ack-isolated`, and refuses to run as root.

## Files
| File | Role |
| --- | --- |
| `payloads.py` | The scenarios. Each runs as the root of its own process tree and logs a ground-truth action timeline. |
| `runner.py` | Runs executions one at a time, records `kbd`'s event feed, writes the corpus. |
| `capture.py` | `StreamEvents` -> JSONL with receive time; records stream disconnects as `{"gap":true}` markers. |
| `labeling.py` | Attributes events to executions (pid + time window), builds leakage-safe splits. |
| `containment_demo.py` | Older single-process demo; not part of the corpus pipeline. |

## Scenarios (`runner.py --list`)
Attacks: `credential_access`, `privilege_escalation`, `process_injection`, `network_c2`, `memory_exploit`, `evasion_slow`, `exfil_staging`, `credential_dump`.
Benign: `benign_compile`, `benign_database`, `benign_web`, `benign_admin`, `benign_idle`, `benign_backup_etc`, `benign_credential_audit`, and
**`benign_admin_privileged`** (hard negatives: `sudo tar` of `/etc` including `/etc/shadow`, `sudo systemctl status`, ...: legitimate work that touches the same files and privilege paths as the attacks).

**Matched pairs** (added after the first baselines): a model must not be able to separate benign from malicious by process *name*, so each pair uses the same tool and differs only in context.

| Pair | Same tool | Benign | Malicious |
| --- | --- | --- | --- |
| tar | `sudo tar czf` | `benign_backup_etc`: whole `/etc` to a normal backup path, checksum-verified, no network | `exfil_staging`: only `/etc/shadow`, `/etc/gshadow`, `/etc/ssh` into a hidden file, then loopback connects |
| shadow read | root read of `/etc/shadow` | `benign_credential_audit`: `grep -c`, `awk`, `wc -l` (counts only) | `credential_dump`: `cat` written to a file, then a connect to port 4444 |

**Benign work that reads secrets AND uses the network.** The benign halves above make no network connection, so "has network activity" separates them from the attacks by construction. `benign_backup_remote` (the same `sudo tar` over `/etc`, then a real upload to a loopback backup host) and `benign_credential_report` (a counts-only `/etc/shadow` audit whose summary is sent to a loopback monitoring endpoint) read the same secrets and move real bytes. Any "secret read plus network in one process tree" rule has to be tested against them. They differ from the attacks in destination (a loopback "backup host" port, not the C2-style ports) and volume, which today's `process_state` telemetry does not carry.

## Running a capture
1. Put `kbd` in **observe-only** mode so automatic containment cannot truncate the attacks (the runner refuses otherwise):
   ```
   sudo systemctl edit kbd        # [Service]  Environment=KB_OBSERVE_ONLY=1
   sudo systemctl restart kbd
   ```
   In this mode `kbd` still scores, alerts and audits, but the BORDERLANDS throttle, `auto_terminate` and exfil auto-NAMESPACE become `OBSERVE_ONLY_WOULD_*` audit entries. Operator/agent containment still works. **Remove the override afterwards.**
2. Run as an ordinary user that can open `/run/kb/kba.sock` (group `kb`):
   ```
   python3 runner.py --ack-isolated --scenarios all --repeats 5 --seed 1 --out corpus
   ```
   `--list`, `--dry-run` show the plan. `--allow-containment` records with containment on (labelled in the manifest).

## Output (`<out>/<run_id>/`)
`events.jsonl` (telemetry, no labels), `labels.jsonl` (one record per execution: scenario, family, kind, root pid, every pid seen, wall-clock window, first malicious action, and `kbd_audit` = what `kbd` itself did about those pids), `actions/<id>.jsonl` (payload timeline), `manifest.json` (host, kernel, package version, feature schema, seed, `containment_active`, kbd stats before/after, sensor summary count).

## Rules for using it
- Labels are ground truth for **targets and metrics only**, never features (`kb-aads/features/schema.py` refuses label-like inputs).
- Split by **execution**, hold out whole scenario **families** (`labeling.split_executions`); never by event or window.
- Treat `{"gap":true}` markers and `stream_gaps` in the manifest as missing telemetry, not as quiet behaviour.
- Execution order is seeded-shuffled so scenario does not correlate with time/drift.
- Unattributed events during a run are **background** (real noise a deployed policy must ignore), labelled benign with no execution.

## Tests
`/path/to/venv/bin/python -m pytest scripts/attack-lab/tests` (no root, no gRPC needed).
