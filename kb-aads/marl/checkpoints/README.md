# Trained checkpoints

Checked into git — each trained policy is confined to its own subdirectory
(e.g. `containment_ppo/`), so committing the actual weights keeps the repo
immediately runnable (clone and go) without requiring a retrain first. Only
~1.8MB for `containment_ppo/`; re-evaluate this choice if a future
checkpoint (e.g. Jury/Healer, or a larger model) is significantly bigger.

Regenerate any checkpoint by running `train_containment.py` (or
`train_containment.ipynb` on Colab, given no local GPU) — loaded at runtime
by `kb-aads/agents/containment.py`. If `containment_ppo/` isn't here,
`ContainmentAgent` falls back to `NONE` (no containment) and reports
`model_loaded: False` — it does not guess.

Expected layout after training:

```
containment_ppo/
  learner_group/learner/rl_module/default_policy/   <- what containment.py actually loads
  ...                                                 <- rest of the Algorithm checkpoint
```
