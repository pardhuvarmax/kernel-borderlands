# features

`schema.py`: the **versioned feature contract** (schema v1) shared by training, offline evaluation and live serving. It lists the features, ranges, clipping and missing-value defaults, refuses label-derived inputs (`event_type`, scenario, target level), and gates checkpoints: a model is only served if its `feature_schema.json` matches. Plan and rationale: [`../../docs/development/control-aads/learned-policy-retraining.md`](../../docs/development/control-aads/learned-policy-retraining.md). `kbd` emits the same keys in `process_state` event metadata.
