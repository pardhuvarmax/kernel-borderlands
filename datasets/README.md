# Datasets

Labelled telemetry captured from the live KB sensor, kept apart from the code that produces it.

| Directory | Contents |
| --- | --- |
| [`attack-lab/`](attack-lab/) | Corpora from the attack-lab scenario runner ([`../scripts/attack-lab/`](../scripts/attack-lab/)) |

**Git tracking:** only the compact tables (Parquet, small CSVs, README, analysis report) are committed. Raw run files, the large `events.csv` and the `.xlsx` copies stay local (git-ignored); regenerate every table with `scripts/attack-lab/export.py`.

**Rules for use:** labels are ground truth for targets and metrics only, never features; split by whole execution and hold out scenario families. The retraining plan is in [`../docs/development/control-aads/learned-policy-retraining.md`](../docs/development/control-aads/learned-policy-retraining.md).
