# Multi-Agent Reinforcement Learning + Agentic LLM Reasoning

MARL system for agent policy learning (Jury, Healer, Containment), plus a fine-tuned agentic LLM for investigative reasoning (Hunter). See [`docs/development/control-aads/aads-intelligence-roadmap.md`](../../docs/development/control-aads/aads-intelligence-roadmap.md) for the full, maintained design and phased implementation plan — this file is a quick-reference summary, not the source of truth; if the two disagree, the roadmap doc is newer and wins.

## RL scope — Jury, Healer, Containment only

Judge, Executor, Patroller, signal relays, and containment militia squad members/leads get **no trained model** — rule-based orchestration or mechanical execution. Only Jury (vote), Healer (restore vs. keep contained), and Containment (target enforcement level) are bounded numeric-action decisions with a computable reward, which is what RL is for here. See the roadmap's per-agent table for the full reasoning per role.

## Framework
- Ray RLlib 2.x (new API stack — `RLModule`/`Learner`, not the legacy `Policy` class)
- Gymnasium environment (`kb-aads/marl/env.py`)
- PyTorch policy networks

## Containment: trained, as of this session (scoped, not full Phase 0)

Unlike Jury/Healer (still stubs), **Containment now has an actual trained-policy pipeline**, built as a stand-in for the roadmap's full Phase 0/1/2 (which needs real eBPF capture from isolated-VM attack-lab runs — that doesn't exist yet). What's real here, not synthetic:

- **Data**: [ADFA-LD](https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-IDS-Datasets/) (Creech & Hu) — real Linux syscall-sequence traces, a host-based dataset matching kb-core's actual observation surface (syscalls), not a network-flow dataset like NSL-KDD/CICIDS (tried first, replaced — network flow doesn't match what KB hunts). Attack categories mapped onto KB's attack-lab scenario names (`scripts/dataset/collect.py`'s `ADFA_CATEGORY_TO_KB_SCENARIO`) — Adduser→privilege_escalation, Hydra_FTP→credential_access, Hydra_SSH→lateral_movement, Java_Meterpreter→process_injection, Meterpreter/Web_Shell→reverse_shell. **Gap, stated plainly**: no ADFA-LD category maps to `memory_exploit.sh` — that scenario has zero training coverage. Benign class also includes real `/proc` telemetry sampled from the dev machine.
- **Pipeline**: `scripts/dataset/collect.py` → `label.py` → `split.py`, all real code, runnable end to end (see their docstrings for exactly what each computed feature means and why — `score`/`score_delta` are a composite z-score over trace length/syscall-diversity/repeat-run-length against ADFA-LD's own Normal-trace statistics, not a random per-category band).
- **Env**: `env.py`'s `ContainmentEnv` — observation is the real `ProcessState`/`KBEvent` wire-field shape, reward is computed from the labeled target vs. action taken (over-/under-containment asymmetry), single-step episodes (a deliberate, documented scope choice for Containment specifically — see the env's docstring for why that's not just the old stub carried forward).
- **Training**: `train_containment.py` (RLlib PPO) / `train_containment.ipynb` (same script, Colab-wrapped — no local GPU on the dev machine, though this env is small enough that CPU training works fine either way).
- **Inference**: `agents/containment.py` loads the resulting checkpoint (`RLModule.from_checkpoint`, inference-only, no `ray.init()`/training stack needed in the agent process) and actually drives `ContainmentAgent`'s decisions — falls back to `NONE` + explicit `model_loaded: False` if no checkpoint has been trained yet, never guesses.
- **Attack-scenario → `ContainmentLevel` mapping** (proposed, not Karthik-confirmed — see `scripts/dataset/label.py`'s docstring for the full reasoning): credential_access→CGROUP, lateral_movement→SECCOMP, privilege_escalation/process_injection→NAMESPACE, reverse_shell→TERMINATE.

Jury and Healer are still the old hardcoded-threshold stubs — this session's scope was Containment only.

## Reward Signals (Jury/Healer — not yet built; Containment's actual reward is in `env.py`'s `_reward()`)
- True Positive:  +1.0 (correctly identified threat)
- False Positive: -0.5 (legitimate process contained)
- True Negative:  +0.1 (safe process correctly ignored)
- False Negative: -1.0 (missed threat)

Requires ground-truth labels the environment can't compute on its own — comes from the attack-lab dataset (Phase 0) and, once in production, the analyst-feedback loop (Phase 6).

## Training Pipeline (Jury/Healer's future path — Containment's actual pipeline is described above)
1. Collect outcomes from production decisions — **vendor-centralized**, not customer-side (Phase 6). Customer deployments never retrain locally; outcome data flows back to the vendor, who retrains and ships periodic checkpoint updates. The transport for that data flow and the checkpoint-distribution mechanism are both still undesigned — see roadmap Phase 6.
2. Compute reward signals per agent (the table above)
3. Update policy networks via RLlib
4. Validate new policy with `kb-checker` — **open question, not yet resolved**: `kb-checker`'s design is explicitly stateless/no-network; what "validating a policy artifact" means under that constraint needs its own design decision (roadmap Phase 5), not assumed here.
5. Deploy to production agents

## Hunter: agentic LLM, not RL

Hunter is a **fine-tuned LLM running a multi-step tool-call loop** (reason → call a tool → observe → repeat → conclude), not a flat single-shot completion and not an RL policy — "agentic" describes inference-time control flow, it doesn't move Hunter into the RL column. Fine-tuning is supervised (imitation learning on labeled trajectories), not reward-driven.

- **Base model candidates**: Phi-3 Mini / Qwen2.5 3B / Mistral 7B, QLoRA fine-tuned. Tool-calling capability is now an explicit selection criterion (it wasn't when these three were first picked) — Qwen2.5's family has comparatively strong native tool-use support, making it the current likely front-runner, pending Karthik's actual evaluation.
- **Tools**: `kb-aads/comms/grpc_client.py`'s `ControlPlaneClient` methods (`get_process_state`, `list_zone`, `stream_events`, `stream_alerts`) — real gRPC calls over `/run/kb/kba.sock`, already implemented. No new client code needed, just exposing these as callable tools via the model's native function-calling format (`apply_chat_template(..., tools=...)`).
- **Iteration cap**: proposed 5 tool calls, with a forced-conclusion-plus-reduced-confidence fallback if the model doesn't converge in time — see roadmap Phase 4.
- **Domain**: security reasoning over behavioral event sequences, specifically the investigation Hunter's own code (`agents/hunter.py`) already sketches: query control plane history → build evidence chain → calculate confidence → submit to jury.

## GPU

Needed for training only (this pipeline, run by the dev team) — not for running the product. Customers/production deployments run inference only (RL policies + the fine-tuned LLM), which is fully functional on CPU; GPU only affects training/inference *speed*, not whether it works. See the roadmap's GPU discussion for the full reasoning.
