# Trained checkpoints

Not checked into git (binary training artifacts) — see `.gitignore`.

Run `train_containment.py` (or `train_containment.ipynb` on Colab, given no
local GPU) to produce `containment_ppo/`, loaded at runtime by
`kb-aads/agents/containment.py`. If `containment_ppo/` isn't here,
`ContainmentAgent` falls back to `NONE` (no containment) and reports
`model_loaded: False` — it does not guess.

Expected layout after training:

```
containment_ppo/
  learner_group/learner/rl_module/default_policy/   <- what containment.py actually loads
  ...                                                 <- rest of the Algorithm checkpoint
```
