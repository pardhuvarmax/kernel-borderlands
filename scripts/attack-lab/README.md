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
| `lidds_runner.py` | Runs real-exploit scenarios from LID-DS 2021 (separate GPL-3.0 checkout) in normal and exploit modes; same corpus format, victim-container pids only. |

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

## Real-byte scenarios (`--scenarios real_bytes`)
The original attacks only `connect_ex()` to a loopback address with no listener, so they transmit **nothing**; a byte counter cannot tell them from silence (corpus `20261105T214545`). These seven move real bytes to a loopback sink inside the payload's own tree, in matched attack/benign pairs (loopback only, no exploit code, files under `--workdir`, ports drawn from the same set for attack and benign so a port cannot leak the label):

| Attack | Size / shape | Matched benign |
| --- | --- | --- |
| `exfil_small_real` | secrets staged with `sudo tar` and uploaded, a few KB | `benign_telemetry_small` (non-secret inventory, same size class) |
| `exfil_slow_real` | 512 B every 4 to 6 s | `benign_telemetry_small` |
| `exfil_bulk_real` | secrets plus a 16 to 48 MiB blob, uploaded (volume looks like a backup) | `benign_backup_bulk` (`/etc` plus the same size of data to a backup host) |
| `c2_beacon_real` | fixed-interval check-ins with replies and an occasional 20 KB result | `benign_heartbeat_real` (same interval, size and ports) |

`--scenarios` also takes groups: `all` (every scenario), `legacy` (the 18 scenarios of the first corpora, to stay comparable with them) and `real_bytes`. Variants come from the seed (rounds, sizes, intervals, ports). Not yet captured on the VM.

## Unattended windows (`batch.py`) and the destination mix
`batch.py` runs ON the VM and does one time-boxed capture window with guaranteed restore: it checks the preconditions (kb-checker hold, no leftover drop-ins, kbd and kb-sensor active), backs up `policy.yaml`, applies the window-only settings (`KB_OBSERVE_ONLY=1` on kbd, `KB_SENSOR_EXIT_STATE=all` and `KB_BYTES_SENT=1` on kb-sensor, `known_destinations` in policy), runs one `runner.py` per seed without starting a seed that would not finish inside `--max-minutes`, and ALWAYS restores (also on error or SIGTERM) and verifies, printing `RESTORE OK` or a loud `RESTORE FAILED`. It needs `--ack-isolated` and `--ack-observe-only` (the operator's approval for the window). `--dry-run` prints the plan.

`known_destinations` is only informative if it does not give the label away. The original scenarios send attacks to `127.0.0.2/.4` and benign work to `127.0.0.3/.5`, so listing the benign hosts would separate them by construction. Therefore: capture the `legacy` group with `--known-hosts ""` (the feature stays 0) and the `v2` group (the 7 real-byte scenarios plus 3 destination-mix scenarios: an attack that uploads to a LISTED host, and benign backups/telemetry to unlisted hosts) with the default `--known-hosts 127.0.0.3,127.0.0.5`. Do not pool the two without keeping that in mind.

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

## Real exploits: LID-DS 2021 (`lidds_runner.py`)
LID-DS ships 15 scenarios with real vulnerable services, normal traffic and exploits, each in Docker. Keep LID-DS in its own checkout (GPL-3.0; never copy it into this repo) and install it as its wiki says (Docker, Sysdig, Python 3.7, `install.sh`, `build_images.sh` per scenario).
```
python3 lidds_runner.py --lidds ~/LID-DS --list
python3 lidds_runner.py --lidds ~/LID-DS --ack-isolated --scenarios all --repeats 10 --seed 1 --out corpus
```
- Same safety rules as `runner.py` (`--ack-isolated`, not as root, observe-only `kbd`), plus passwordless `sudo -n` for Docker and the LID-DS interpreter.
- Each scenario runs in two modes: `normal` (kind `benign`) and `exploit` (kind `attack`), so every exploit has false-positive runs on the same service.
- An execution's `pids` are the processes in the **victim container** (cgroup membership, then `labeling.expand_pids`); exploit and normal-traffic containers are kept in `pids_by_role` and never count as the victim.
- `first_malicious_ns` = the exploit container's start time from Docker (an upper bound for time-to-detect).
- Victim detection is by container name or image; if a run prints "no victim container identified", pass `--victim-match <regex>`. Check each scenario's README: its CLI may differ from the default `main.py 1 <s> 0` / `main.py 1 -1 1` (override with `--cmd-template`).
- Activity of the attacker's containers on this host is counted as background by `analyze.py`; keep that in mind when reading background-noise numbers.

## Tests
`/path/to/venv/bin/python -m pytest scripts/attack-lab/tests` (no root, no gRPC needed).

## Training table (`build_training_table.py`)

Merges runs into `features.parquet` (schema features only, built through `kb-aads/features/schema.py`), `labels.parquet` (ground truth and the execution-level split, same keys) and `manifest.json` (commit, row counts, per-run feature provenance). Default: the three plan runs `20261031T183320`, `T193756`, `T201927` (230 executions, 886,140 `process_state` rows). Features a run's sensor never emitted (`dest_*`) are schema-default-filled and marked `absent`; `tree_*` are **reconstructed** by replaying the stream through the rules of `kb-control-plane/internal/controlplane/tree.go`, with two approximations documented in the script header. Outputs are derived and git-ignored. Run: `python3 scripts/attack-lab/build_training_table.py [--out DIR] [RUN ...]` (needs numpy, pandas, pyarrow). Tests: `tests/test_build_training_table.py`.
