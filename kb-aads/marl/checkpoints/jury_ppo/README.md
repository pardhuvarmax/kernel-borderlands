# jury_ppo

An RLlib PPO checkpoint (Jury CONTAIN/ALLOW vote policy), as written by `../../train_jury.py`. The nested directories (`env_runner/`, `learner_group/`, ...) are RLlib's own checkpoint layout and are not meant to be edited by hand.

**Not served by default.** This checkpoint was trained on a label-derived `event_type` that `kbd` never emits, so on live data it answers ALLOW/NONE for everything. The loaders refuse it unless it ships a matching `feature_schema.json` (see [`../../../features/schema.py`](../../../features/schema.py)); `KB_ALLOW_LEGACY_POLICY=1` overrides this for research only. Plan: [`../../../../docs/development/control-aads/learned-policy-retraining.md`](../../../../docs/development/control-aads/learned-policy-retraining.md).

The `.pkl` files are pickles (code runs when loaded): the package ships an integrity manifest, and you should only load checkpoints you trust.
