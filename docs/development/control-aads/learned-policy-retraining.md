# Learned Policy Retraining: Feature Contract, Gates and Plan

- **Status:** Plan + first enforcement steps implemented (schema, checkpoint gate, kbd feature export). Corpus capture and retraining are NOT done.
- **Code:** `kb-aads/features/schema.py`, `kb-aads/consensus/jje.py` (`_load_jury_policy`), `kb-aads/agents/containment.py` (`_load_policy`), `kb-aads/agents/hunter.py` (`use_learned_policy`), `kb-control-plane/internal/controlplane/controlplane.go` (`OnProcessState`)
- **Related:** `kb-aads/marl/README.md` (legacy results), `aads-intelligence-roadmap.md`

## 1. The defect (train-serving skew)

The shipped Jury and Containment PPO checkpoints observe `(score, zone, uid_is_root, score_delta, event_type)`. In training, `event_type` was an engineered code per attack scenario, derived from the label (`scripts/dataset/label.py`, `KB_SCENARIO_EVENT_TYPE`; `marl/README.md` documents that giving each scenario its own code is what lifted CGROUP/SECCOMP accuracy). `kbd` never emits such a field, so serving supplies `0`.

Measured on the shipped checkpoints (Jury / Containment, `event_type = 0`): score 92, zone BORDERLANDS, root -> ALLOW / NONE. The same observation with a scenario code supplied flips to CONTAIN / level 2. The model is not reading telemetry; it is reading the answer.

Consequences: the 84.4% overall accuracy and 0.0% under-containment in `marl/README.md` measure the legacy offline table only. They are **not** evidence of live performance and must not be carried into the journal manuscript as such. The preprint stays unchanged.

## 2. Rules

1. Labels (attack, scenario, target level) are training targets and reward inputs only, never model inputs. `features/schema.py` raises on label-like keys (`FORBIDDEN`).
2. One feature contract (`SCHEMA_VERSION = "1"`) for training, offline eval and serving: names, order, ranges, clipping and missing-value defaults live in `FEATURES`. Any change bumps the version.
3. A checkpoint serves only if it ships `feature_schema.json` equal to the serving schema (`gate_checkpoint`). Legacy checkpoints are refused (`KB_ALLOW_LEGACY_POLICY=1` is a research-only override, never for production).
4. Deterministic containment stays authoritative. `policy.use_learned` in `config/agents.yaml` defaults to `false`; the live path uses the Jury confidence threshold and `pipeline/flow.py:level_for` (TERMINATE only in BORDERLANDS at confidence >= 0.85, matching `kbd`'s gate).
5. Hard safety (CPM/CWP protected processes, PID 1, kernel threads, authorization allowlist, confidence gate) is enforced in `kbd` and the sensor and is outside any agent's control or reward.

## 3. Schema v1 (what exists today)

Served from `KBEvent{event_type:"process_state"}.metadata` (`feature_schema = "1"`, test `TestOnProcessState_EmitsFeatureSchemaV1`):

`score, zone, is_root, score_delta, dim_process, dim_syscall, dim_privilege, dim_file, dim_network, dim_memory, telemetry_gap`.

All are computed by the sensor/kbd from observed behaviour. `telemetry_gap` defaults to 1 (unknown means unsure). The sensor does not yet report per-window drop counts per process, so `telemetry_gap` is currently derived only from missing dimensions; wiring the ring-buffer drop accounting through is open work.

Candidate features that do **not** exist in the sensor yet (implement before adding to the schema, then bump the version): `credential_change_count`, `sensitive_file_access_count`, `network_anomaly_score` (beyond `dim_network`), `memory_risk_flags` (mmap/mprotect/injection evidence), `sequence_evidence` (ordered events in a window).

## 4. Pipeline to build

1. **Capture.** Attack lab on an isolated VM (root): benign workloads (web, DB, compile, desktop), privilege escalation, process injection, suspicious network, credential access, evasion. Record the sensor's own `process_state` stream plus timestamps. `scripts/attack-lab/` currently has only `containment_demo.py`; the scenario scripts listed in older docs do not exist.
2. **Label independently.** Labels come from the scenario runner's ground truth (which PID did what, when), written to a separate file keyed by `(execution_id, pid, window)`. The feature builder never reads it.
3. **Split before windowing.** Split by execution and by scenario family (hold out whole families for generalisation), then generate windows. No window from a held-out execution may appear in training.
4. **Baselines first.** Deterministic rules (current fixed policy), logistic regression, tree ensemble with calibration. PPO is justified only if it beats these on the independent set; the current decision is single-step, which is a contextual bandit, so a calibrated classifier with an abstain option is the first thing to beat.
5. **Reward (if RL is kept).** Penalise missed/late containment, unnecessary containment of legitimate processes, action severity and irreversibility, time to *applied* enforcement (sensor ack), service disruption, and decisions under incomplete telemetry. Hard constraints (protected processes, authorization) are constraints, not reward terms.
6. **Serve through the real path.** Export the model with `feature_schema.json` (`schema.write_schema`), run the offline evaluation through the same `build_vector` + agent inference code the swarm uses, and include the `score=92 / BORDERLANDS` case. A score of 92 does not by itself imply TERMINATE; the test checks the decision is evidence-based and proportionate (root, dimension mix, telemetry gap, process criticality), not one fixed output.
7. **Shadow mode.** Run the learned policy beside the deterministic one, log both decisions and disagreements (audited, no enforcement), then isolated-VM enforcement tests with rollback.

## 5. Gates before `policy.use_learned: true`

Evaluated on independent executions/scenarios, with confidence intervals and repeated trials, against deterministic and supervised baselines:

- attack recall and missed-containment rate; false-positive rate and legitimate-process disruption;
- calibration (reliability, abstain behaviour);
- p50/p95/p99 time to *applied* enforcement;
- behaviour under telemetry loss and flood (`telemetry_gap` set, no silent drop);
- no regression of the deterministic safety properties; reproducible model version, schema, training config and report stored with the checkpoint.

## 6. Agent roles (what to measure, not assume)

Patroller: alert noise vs missed transitions. Hunter: whether its evidence changes decisions. Jury: calibration and abstention. Containment: proportionality over a sequence. Militia/Executor: staged execution under partial failure (the ladder halts at the first refusal). Healer: restore only with recovery evidence. Judge/Courthouse: quorum latency and stall recovery. Ablate each (with/without Jury, staged vs direct, safety gates) before claiming it earns its complexity.
