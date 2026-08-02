# Kernel Borderlands Work Report — August 2, 2026

* **Engineers**: Karthik (AI & Agentic Systems, kb-aads Primary Maintainer), PardhuVarma (ML & Systems, kb-aads Collaborator)
* **Subsystems involved**: AADS Swarm (`kb-aads`), dataset tooling (`scripts/dataset/`), Colab CLI training workflow

---

## 📂 Executive Summary

Prior to this session, `kb-aads`'s Ray actor/JJE scaffolding ran end-to-end but every decision point was a stub — including Containment, whose `tick()` did nothing but set a static status string (see `docs/development/control-aads/aads-intelligence-roadmap.md`). This session took **Containment specifically** from stub to a genuinely trained, verified-working RL agent: a real dataset pipeline, a fixed Gymnasium environment, RLlib PPO training (run twice, with a real bug found and fixed between runs), a trained checkpoint loaded into `ContainmentAgent` for live inference, and a live demo against the actual running `kb-core`/`kb-control-plane` pipeline on this machine.

**Scope, stated plainly**: this is not the roadmap's full Phase 0-2 (that needs real eBPF capture from isolated-VM attack-lab runs, which doesn't exist yet). It's an honestly-scoped stand-in using real public data instead. Jury and Healer are untouched — still the old hardcoded-threshold stubs. See "What's still stubbed" below.

---

## 🛠️ Key Achievements

### 1. Real dataset pipeline (`scripts/dataset/`)

- **`collect.py`**: Downloads [ADFA-LD](https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-IDS-Datasets/) (Creech & Hu) — real Linux syscall-sequence traces, a host-based IDS dataset matching kb-core's actual observation surface (syscalls at the process level). Pulled from a public GitHub mirror since no Kaggle API credentials are configured on this machine. Also samples real `/proc` telemetry (load, network throughput, process count) from this dev machine for benign-class diversity.
- **First attempt used NSL-KDD (network-flow data) — correctly rejected mid-session.** KB hunts process/syscall behavior (`privilege_escalation.sh`, `reverse_shell.sh`, `lateral_movement.sh`, `credential_access.sh`, `memory_exploit.sh`, `process_injection.sh` per `scripts/attack-lab/README.md`), not network flow. Switched to ADFA-LD, which actually matches.
- **`label.py`**: Maps ADFA-LD's 6 attack categories onto 5 of KB's 6 attack-lab scenarios (`memory_exploit.sh` has no ADFA-LD equivalent — stated gap, zero training coverage for that scenario) via `ADFA_CATEGORY_TO_KB_SCENARIO`. Computes `score`/`score_delta` as a real composite z-score (trace length, syscall diversity, longest-repeat-run) against ADFA-LD's own Normal-trace statistics — not a random per-category band. The first scoring approach tried (single-syscall rarity) was empirically degenerate (near-zero for every trace, verified by direct measurement) and was replaced with this composite statistic after measuring which per-trace features actually separate categories.
- **`split.py`**: Stratified train/val/test split by category (a plain shuffle-split risked zero `u2r`/rare-category rows in test, given ADFA-LD's real class imbalance — 5265 normal vs. as few as 91 `privilege_escalation` rows).

### 2. Fixed `ContainmentEnv` (`kb-aads/marl/env.py`)

Replaced the original `AADSEnv` stub (single-step, placeholder observations, `+1.0`/`0.1` hardcoded reward) with a real Gymnasium env: observation is the actual `ProcessState`/`KBEvent` wire-field shape (`score`, `zone`, `uid_is_root`, `score_delta`, `event_type`), reward is computed from the labeled target vs. action taken with an explicit over-/under-containment asymmetry. Single-step episodes remain — a deliberate, documented scope choice for Containment specifically (a per-alert classification, not a multi-tick trajectory the way Jury's consensus voting is), not the old stub carried forward unexamined.

### 3. RLlib PPO training, via `colab` CLI

- Training run via `kb-aads/marl/train_containment.py` (RLlib PPO), executed remotely on a Colab CPU session using the `colab` CLI (`kb-aads/marl/COLAB_CLI_TRAINING.md`, `remote_train_driver.py`) — no local GPU on the dev machine; confirmed this env doesn't need one (small tabular observation/action space, CPU-native per `marl/README.md`'s existing GPU section).
- **Fixed a real upstream bug found while setting this up**: `google-colab-cli`'s `colab install` crashed with `AttributeError: module 'jupyter_kernel_client' has no attribute 'KernelClient'` — `jupyter_kernel_client` 1.0.0 renamed/removed the class the CLI expects. Pinned to `jupyter_kernel_client==0.15.0` in the tool's isolated `uv` venv, which restored the expected API.
- **First training run**: 97.8% test accuracy overall, but only 60-73% specifically on `CGROUP`/`SECCOMP`.
- **Root-caused and fixed**: `credential_access` (→CGROUP) and `lateral_movement` (→SECCOMP) shared the same engineered `event_type` code and `zone` floor, leaving the policy almost nothing to distinguish them by besides noisy score features. Fixed by giving each of the 6 categories (normal + 5 KB scenarios) a distinct `event_type` code (`KB_SCENARIO_EVENT_TYPE` in `label.py`, observation-space bound widened 0-3 → 0-5 in `env.py`), then retrained from scratch (kernel restarted first, so the fix actually took effect — module caching would otherwise have silently reused the old `env.py`).
- **Final (second) training run** — see Results below.
- Full terminal transcript of both runs logged verbatim at `kb-aads/marl/session.log`.

### Results (final, second run)

| Level | Accuracy |
|---|---|
| NONE | 82.2% (791 samples) |
| CGROUP | 100.0% (25 samples) |
| SECCOMP | 100.0% (27 samples) |
| NAMESPACE | 97.1% (35 samples) |
| TERMINATE | 100.0% (30 samples) |
| **Overall** | **84.4%** (908 samples) |
| **Under-containment rate** | **0.0%** |

Trade-off from the fix: overall accuracy dropped (97.8%→84.4%), entirely from `NONE` (100%→82.2%) — the policy became more willing to over-contain borderline-normal traffic. Every attack category improved to 97-100%, and under-containment (missing a real threat) dropped to zero. For a containment system, over-caution on benign traffic is the safer failure mode than a missed threat, so this trade was accepted as-is rather than re-tuned further tonight.

### 4. Live inference wiring (`kb-aads/agents/containment.py`)

`ContainmentAgent` now loads the trained checkpoint via `RLModule.from_checkpoint` (inference-only — no `ray.init()`/training stack needed in the agent process) and drives real decisions in `handle_message`. Falls back to `NONE` + explicit `model_loaded: False` if no checkpoint exists yet, rather than guessing. Verified multiple ways:
- Direct unit-style test: one synthetic observation per KB scenario, all 6 decisions correct (benign→NONE, credential_access→CGROUP, lateral_movement→SECCOMP, privilege_escalation/process_injection→NAMESPACE, reverse_shell→TERMINATE).
- Full swarm run (`python main.py`) with the checkpoint in place — Ray starts, all 7 role actors spawn, `ContainmentAgent`'s constructor successfully loads the RLModule (confirmed via the `RLModule` deprecation warning, which only fires on an actual checkpoint load), no crashes over the observed run window.

### 5. Live pipeline demo against the real system

With `kb-core`'s eBPF sensor (`sudo ./build/kbd_sensor`) and `kb-control-plane` (`KB_DEV=true ./bin/kbd --db ./data/state-devrun.db`) actually running on this machine tonight:
- Confirmed `kbd`'s dev database already had real, previously-persisted process state (87-118 real processes) queryable via `ControlPlaneClient.list_zone`/`get_process_state` over the real `kba.sock` gRPC channel — no synthetic data.
- Built `kb-aads/demo/live_containment_monitor.py`: a long-running driver that streams real `KBEvent`s from `kb-control-plane` (`StreamEvents`), fetches each PID's real `ProcessState`, and feeds it to a persistent `ContainmentAgent` actor, logging every decision continuously. Ran it live against real system processes (`sudo`, `kbd_sensor`, `ray-dashboard-*`, `avahi-daemon`, `node`, `ps`, ...) — decisions matched the documented test-set trade-off (mostly `CGROUP`-level caution on benign real processes, never under-containing).
- **Caught and fixed a real correctness bug in the demo script itself** before leaving it running: `kb-control-plane` returns a zero-value default `ProcessState` (not an error) for a PID it hasn't scored yet (typically a very short-lived process). The default proto's `uid` is `0`, which the naive `uid_is_root` feature misread as "running as root," producing spurious `NAMESPACE` decisions. Fixed by treating `comm == ""` as the actual "not found" signal and skipping those events instead of feeding fabricated observations to the policy.
- Stopped cleanly at the end of the session (process killed, Ray processes cleaned up) — not left running.

### 6. Environment/tooling fixes along the way

- **`.gitignore` had a dead rule**: `kernel-borderlands/scripts/dataset/output/raw` never matched anything (wrong path prefix relative to where `.gitignore` actually lives). Fixed to `scripts/dataset/output/raw/`. Added rules for `kb-aads/marl/checkpoints/*` (binary training artifacts) and `scripts/zips/` (packaged bundles), both regenerable, neither meant to be committed.
- **`kbd` failed to start** (`attempt to write a readonly database`): its default db path (`/var/lib/kbd/state.db`) is `root:root`-owned, not writable by a non-root user. Resolved by pointing it at the repo's existing writable dev database (`--db ./data/state-devrun.db`) instead of running `kbd` itself as root — keeps its created sockets owned by the regular user, so `kb-aads` (also non-root) can connect without a second permission fight.
- **`kbd` then failed on an SSH config check** (`production mode error: directory /etc/kb is not accessible/writable and KB_DEV is not set to true`) — resolved by setting `KB_DEV=true`, an existing, intentional dev-mode escape hatch in `internal/ssh/config.go`, not a workaround.

---

## What's still stubbed (not touched this session)

- **Jury** (`agents/hunter.py`'s consensus counterpart) and **Healer** — still hardcoded-threshold/static-string stubs, per `marl/README.md`.
- **Hunter** — still the four bare `# TODO`s described in the roadmap; no agentic LLM work happened tonight.
- **Patroller/Judge real event consumption** — `stream_events`/`stream_alerts` are real, callable gRPC methods, but no agent in the actual swarm (`main.py`'s `RaySwarmOrchestrator`) calls them yet. Tonight's live demo (`live_containment_monitor.py`) deliberately bypasses the entire Patroller→Hunter→Judge/Jury consensus chain and calls Containment directly on every event — explicitly documented in that script's own docstring as a demo shortcut, not how the finished product should route decisions.
- **`event_type` mapping from kb-core's real event taxonomy**: kb-core's real `KBEvent.event_type` is a string from its own eBPF vocabulary (e.g. `"exec"`, `"connect"`); there is no built mapping from that vocabulary to the 6 category codes Containment's policy was actually trained on. The live demo hardcodes `event_type=0` for every real event, so live decisions are currently driven mainly by real `score`/`zone`/`uid` signal, not a real event-type match.

---

## Artifacts

- `scripts/dataset/{collect,label,split}.py` — the pipeline
- `scripts/dataset/output/{train,val,test}.csv` — the labeled splits (also bundled in `scripts/zips/containment_training_bundle.zip`, gitignored)
- `kb-aads/marl/env.py`, `train_containment.py`, `train_containment.ipynb`, `remote_train_driver.py`, `COLAB_CLI_TRAINING.md`
- `kb-aads/marl/session.log` — full terminal transcript of both training runs
- `kb-aads/marl/checkpoints/containment_ppo/` — the trained checkpoint (gitignored, binary)
- `kb-aads/agents/containment.py` — live inference wiring
- `kb-aads/demo/live_containment_monitor.py` — live-pipeline demo driver
