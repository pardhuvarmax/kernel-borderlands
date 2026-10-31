# Attack-Lab Test Suite: KB Benchmark Framework

Status: **proposal / design**. Nothing in sections 4 to 9 is implemented. This file is a plan, not a
specification; where it disagrees with `docs/specifications/` or `docs/architecture/`, those win
(see CLAUDE.md, documentation precedence). Section 2 describes what exists today and was verified
against the repository; everything else is marked *proposed*.

Source: operator design discussion (three validation stages, two execution pathways, a 150-CVE
registry). Figures quoted from that discussion about public CVE counts were not verified and are
deliberately omitted.

## 1. Purpose and the one rule that matters

KB is the **system under test**. The benchmark framework is an **independent evaluator**. It must
never influence detection ground truth, never tune KB to the test set, and never manufacture
successful results. Everything else follows from that.

Goals:

1. Measure, reproducibly, what KB can *observe*, *classify*, *attribute* and *contain*.
2. Separate three different engineering problems that a single "detection rate" hides:
   - **Detected**: KB observed the activity and classified it correctly.
   - **Observed, not detected**: the telemetry exists in the corpus but the rules/agents did not flag it.
   - **Not observable**: the needed telemetry was never collected (a sensor gap).
3. Keep the framework a *validation* tool. It adds no defence features to KB.

## 2. What exists today (verified)

Location: `scripts/attack-lab/` (see its README). Not a CVE tool: it is a **behavioural simulation lab**.

| Piece | File | Role |
| --- | --- | --- |
| Scenarios | `payloads.py` | 18 scenarios (8 attack, 10 benign incl. matched pairs); loopback-only; no real exploit code |
| Runner | `runner.py` | Executes scenarios; requires `--ack-isolated`; refuses to run as root; removes its scratch per execution |
| Capture | `capture.py`, `labeling.py` | Window + process-ancestry attribution; leakage-safe train/test split by execution |
| Report | `analyze.py`, `export.py` | Per-family table with Wilson intervals; CSV/Parquet/xlsx + data dictionary |
| Baselines | `baselines.py`, `tree_oracle.py` | Fixed rules vs logistic regression vs gradient-boosted tree; tree-level oracle |
| Datasets | `datasets/attack-lab/<run>/` | Parquet + small CSVs + reports tracked; raw and large tables local |

Existing mechanisms the benchmark must reuse rather than reinvent:

- **Observe-only**: `KB_OBSERVE_ONLY=1` on `kbd` (audits `OBSERVE_ONLY_WOULD_*`, no automatic containment). Default off.
- **Manual containment**: `kbctl process isolate` and restore, over `/run/kb/kba.sock`. Operator interfaces: `kbctl`, `kb-tui`, `kb-dashboard`, `kb-mcp`.
- **Agentic path**: `kb-aads` live pipeline (Hunter, Judge, Executor; staged CGROUP then TERMINATE). `policy.use_learned` defaults to false.
- **Audit**: `kbctl audit export` / `audit verify` (hash-chained).
- **Sensor exit-state**: `KB_SENSOR_EXIT_STATE=all` publishes final per-process state, which the lab needs for ground-truth joins.
- **Allowlist**: exempts listed comms from *automatic* containment only; never rewrites zones.

Findings so far that shape this plan (CHANGELOG 1.1.0; corpora `20261031T183320`, `T193756`, `T201927`):

- The fixed per-process rule engine flags 30/40 attacks and 25/50 benign runs at SUSPICIOUS or higher; only `process_injection` reaches BORDERLANDS. `network_c2` and `memory_exploit` are not flagged.
- Matched pairs that share a tool (`exfil_staging` vs `backup_etc` / `backup_remote`, `credential_dump` vs `credential_audit` / `credential_report`) are not separated by any process-level rule or model on schema v1.
- "File plus network in one process tree" is 5/5 for the attacks **and** 5/5 for the benign network-using scenarios, so it is not a usable rule alone.
- Lesson for any new benchmark content: **every attack needs a benign twin that uses the same tools and the same network behaviour**, otherwise the benchmark measures the author's scenario design, not KB.

## 3. Stage model (the three validation conditions)

These are **test conditions**, not new KB operating modes.

| Stage | Name | Question | Mapping to existing KB |
| --- | --- | --- | --- |
| S1 | Observe Only | Can KB see and correctly identify the behaviour? | `KB_OBSERVE_ONLY=1`; evaluate rule engine, audit, would-contain records |
| S2 | Containment Only | Can KB contain the designated process without collateral damage? | Containment invoked explicitly (`kbctl process isolate`, or `kbd` automatic containment limited to a designated test process) |
| S3 | Active KB Defense | Does the complete loop (detect, decide, contain, recover) work? | Default `kbd` plus `kb-aads` Executor, within explicit authorisation |

Two execution pathways, compared under equivalent conditions:

- **Manual flow**: an operator drives KB's existing capabilities (`kbctl`, TUI).
- **AADS**: the existing agent swarm performs its authorised workflow.

Up to 150 CVEs x 3 stages x 2 pathways = 900 combinations. Many are not applicable or not safely
reproducible; **record applicability separately from outcome** (an `n/a` is not a failure).

### Open architectural question (needs a maintainer decision, nothing changed)

The discussion proposes a separate "policy controller / stage manager" that *enforces* the stage so
the agents cannot exceed it. KB has no such component today: observe-only is a `kbd` environment
switch, and S2 versus S3 has no enforced distinction (the same `kbd` and Executor run in both). Two
options:

1. **External lock (recommended first step).** The harness sets the mode by configuration (the
   observe-only drop-in, the allowlist, the Executor's staged-action limit) and *verifies* it
   before each run from `kbd`'s own state and audit. No KB code changes; stronger enforcement
   comes later.
2. **First-class stage in `kbd`.** A real policy-controlled stage setting. This changes behaviour
   and public configuration and must go through the specs first.

Per CLAUDE.md this is not implemented or decided here.

## 4. CVE registry (proposed)

A permanent, version-controlled dataset, e.g. `datasets/attack-lab/cve-registry/registry.yaml`,
one record per entry. Metadata only; it never contains exploit code.

```yaml
cve_id: CVE-YYYY-NNNNN
component: linux-kernel            # or sudo, polkit, runc, ...
subsystem: filesystem              # filesystem | netfilter | mm | ipc | ...
class: memory-corruption           # see section 5
severity: high                     # from NVD/CVSS, as published
affected: {source: NVD, ranges: "..."}
fixed_in: "..."
references: [advisory, upstream-patch, analysis]
category: A | B | C | D            # section 5; only A counts as a reproduction
lab:
  environment: isolated-vm         # disposable, no route to anything real
  kernel_under_test: "..."         # exact version; patch status recorded
  reproduction_available: true|false
expected_observations:             # derived from the technical analysis, then validated
  - {signal: uid_transition, expected: true}
  - {signal: file_modification, expected: true}
benign_twin: <scenario id>         # mandatory (section 6)
results: {s1: pending, s2: pending, s3: pending}
provenance: {run_id, kb_version, feature_schema, date, operator}
```

Selection sources: kernel.org CVE announcements, NVD, CISA KEV (prioritise confirmed in-the-wild
exploitation), Ubuntu CVE tracker, Debian security tracker. Deduplicate, verify technical
relevance, then select. The kernel's own CVE process assigns identifiers to a broad range of
fixes, so a CVE count is not a count of exploitable vulnerabilities.

Proposed target mix for 150 entries (selection targets, not 150 unique techniques):

| Class | Target |
| --- | --- |
| Privilege escalation | 20 |
| Memory corruption | 20 |
| Use-after-free | 15 |
| Race conditions | 15 |
| Filesystem | 15 |
| Network stack / Netfilter | 15 |
| Container / isolation escape | 15 |
| Syscall / ioctl / kernel interface | 15 |
| Information disclosure | 10 |
| Credential / permission manipulation | 10 |

## 5. Entry categories (credibility)

| Cat | Meaning | Counts as a reproduction? |
| --- | --- | --- |
| A | Real vulnerability reproduced in an isolated, disposable environment | **Yes** |
| B | Behaviour simulated without exploiting the flaw (what `scripts/attack-lab` does today) | No |
| C | Replay of recorded telemetry from a documented exploitation | No |
| D | Metadata only, not yet validated | No |

Practical consequence: the current lab VM runs Ubuntu 24.04, kernel 6.8.0-139, which is patched for
the historical examples under discussion (Dirty COW, Dirty Pipe, PwnKit, Baron Samedit and similar).
**Category A is not possible on it.** It would need separate throwaway guests on affected kernel
versions, with no route to the host's network or any other system. Until those exist, honest
reporting is "B" for everything, and the report must say so.

## 6. Experiment design rules

1. **Isolation.** Disposable VM, no external targets, no production systems; payloads loopback-only (as today). Existing guards stay: `--ack-isolated`, refuse root, scratch cleaned per run. A category A guest additionally needs snapshot-and-discard, no shared folders, and no network beyond the harness.
2. **Authorisation.** Category A execution needs an explicit written go-ahead per CVE from the operator; the harness does not run exploits on its own initiative. Exploit code is not stored in this repository's registry; each reproduction script is reviewed separately before it exists.
3. **Benign twin per entry.** Same tooling and same network behaviour, legitimate purpose (lesson from section 2).
4. **Ground truth stays out of the model.** Labels (`label_*`, `split`) are targets and metrics only. No label-derived features. The existing leakage-safe execution-level split applies; whole families held out.
5. **Preserve raw telemetry** for independent re-evaluation; record the KB version, feature schema, kernel and configuration per run.
6. **Repeats.** At least 5 per scenario (the current minimum); report intervals, not bare percentages. n is small: results are descriptive, not performance claims.
7. **No self-fulfilment.** Tuning KB thresholds or rules on a benchmark run invalidates that run's S1 score; keep a frozen evaluation set (a held-out family or CVE subset) never used for tuning.
8. **Stage lock verified.** Before every run, assert the stage condition from `kbd`'s state/audit and abort on mismatch (S1: observe-only on and no containment actions; S2/S3: authorisation recorded).

## 7. Metrics

| Metric | Definition |
| --- | --- |
| Detection rate | Attack executions reaching a defined zone (state it: SUSPICIOUS+, BORDERLANDS+) / attack executions |
| False-positive rate | Benign executions (and background processes per minute) flagged |
| Event coverage | Expected signals actually present in telemetry / expected signals |
| Detection latency | First malicious action to first `kbd` zone audit (today: median 3 ms, max 206 ms on flagged attacks) |
| Attribution accuracy | Flagged process is the true originator or a descendant |
| Correlation accuracy | Related events across a process tree joined correctly |
| Classification accuracy | Behaviour class matches the label (needs a classifier output first) |
| **Observability gap** | What the vulnerability did versus what KB recorded; the list of missing signals |
| Containment (S2) | Contained within a bound; no collateral on unrelated processes; restore works |
| Defence (S3) | Time to neutralise, recovery verified, audit chain intact |
| Overhead | Sensor CPU, event loss/gaps, journal volume, latency under load |
| Cross-pathway consistency | Manual vs AADS agreement per entry; every discrepancy recorded with both audit trails |

Report three outcome buckets per entry: detected / observed-not-detected / not observable.

## 8. Promotion gates

Do not unlock a stage because the previous one finished.

- **S1 to S2**: all registered S1 entries run; telemetry coverage and false-positive rate within agreed bounds; observability gaps triaged.
- **S2 to S3**: containment reliable and boundaries tested; zero unintended impact on unrelated processes across the set; restore verified.
- **S3 to production use**: regression tests including flood/overload tests, authorisation controls, audit review, recovery validation, independent security review.

Keep each stage's results as separate, never-overwritten records (`KB-AL150-S1`, `-S2`, `-S3`).
Complete S1 for all entries before starting S2. Containment must not be described as fixing the
vulnerability: a vulnerable kernel stays vulnerable until patched.

## 9. Interface (proposed)

The discussion used `kb attack-lab ...`. No such command exists; the real operator CLI is `kbctl`,
and the lab is driven by `scripts/attack-lab/runner.py`. Proposed, to be built on those:

```
runner.py list-cve | info <CVE> | validate <CVE>        # registry only, no execution
runner.py run <CVE|scenario> --stage S1 --pathway manual|aads --ack-isolated
runner.py replay <dataset>                               # category C
analyze.py / export.py <run>                              # unchanged
benchmark report <experiment-id>, compare <a> <b>         # new: stage and pathway comparison
```

## 10. Build order (recommended)

1. Registry schema and validator; import 150 candidates as category D; no execution.
2. Extend category B coverage using matched pairs (the already-measured gaps: `network_c2`, `memory_exploit`, tree-level evidence, destination class).
3. S1 harness hardening: stage-lock verification, frozen evaluation set, experiment identity.
4. Category C replay of recorded telemetry.
5. Category A only after separate isolated affected-kernel guests exist and each CVE is authorised.
6. S2, then S3, behind the promotion gates; manual and AADS pathways in parallel.
7. Flood/overload and performance tests (existing roadmap item) as the stress suite.

## 11. Known gaps and risks

- No CVE-capable guest exists; category A is currently impossible.
- The schema-v1 features cannot distinguish the matched pairs (no destination class, bytes sent, sequence evidence); adding them changes the C/Go wire contract and must follow `docs/architecture/kbd-contracts.md`.
- Per-process rule evidence is not joined across child processes; tree aggregation changes the spec state machine and is undecided.
- `kb-checker` is held down by decision; any benchmark that relies on a watchdog cannot include it.
- Shipped PPO checkpoints are trained on label-derived `event_type` and are refused by the feature gate; learned-policy results are out of scope until retraining (`docs/development/control-aads/learned-policy-retraining.md`).
- Sample sizes are tiny; nothing here supports a claim about other hosts or attackers.

## 12. Documentation consulted

`CHANGELOG.md` (1.1.0 entries), `scripts/attack-lab/README.md`, `docs/development/control-aads/learned-policy-retraining.md`,
`kb-op/kbctl` command definitions, and the lab reports under `datasets/attack-lab/`. No file under
`docs/specifications/` describes stages or a CVE registry; this is new, undocumented architecture.
