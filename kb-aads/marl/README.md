# Multi-Agent Reinforcement Learning + Agentic LLM Reasoning

MARL system for agent policy learning (Jury, Healer, Containment), plus a fine-tuned agentic LLM for investigative reasoning (Hunter). See [`docs/development/control-aads/aads-intelligence-roadmap.md`](../../docs/development/control-aads/aads-intelligence-roadmap.md) for the full, maintained design and phased implementation plan — this file is a quick-reference summary, not the source of truth; if the two disagree, the roadmap doc is newer and wins.

## RL scope — Jury, Healer, Containment only

Judge, Executor, Patroller, signal relays, and containment militia squad members/leads get **no trained model** — rule-based orchestration or mechanical execution. Only Jury (vote), Healer (restore vs. keep contained), and Containment (target enforcement level) are bounded numeric-action decisions with a computable reward, which is what RL is for here. See the roadmap's per-agent table for the full reasoning per role.

## Framework
- Ray RLlib 2.x
- Gymnasium environment (`kb-aads/marl/env.py` — currently a stub: single-step episodes, placeholder observations, a reward that doesn't distinguish TP/FP/TN/FN; needs the fixes in the roadmap's Phase 1 before real training)
- PyTorch policy networks

## Reward Signals
- True Positive:  +1.0 (correctly identified threat)
- False Positive: -0.5 (legitimate process contained)
- True Negative:  +0.1 (safe process correctly ignored)
- False Negative: -1.0 (missed threat)

Requires ground-truth labels the environment can't compute on its own — comes from the attack-lab dataset (Phase 0) and, once in production, the analyst-feedback loop (Phase 6).

## Training Pipeline
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
