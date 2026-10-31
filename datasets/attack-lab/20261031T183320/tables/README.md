# Tables

Analysis-ready exports of this run. Column definitions are in [`../README.md`](../README.md).

| Table | Rows are | Formats tracked in git |
| --- | --- | --- |
| `events` | `process_state` / `zone_transition` events with telemetry and `label_*` ground truth | Parquet (the 53 MB CSV and the `.xlsx` stay local) |
| `executions` | one scenario execution (window, pids, peak score, max zone, kbd audit, split) | Parquet, CSV |
| `kbd_audit` | what `kbd` audited for each execution's processes | Parquet, CSV |
| `splits` | proposed train/test assignment (whole executions, families held out) | Parquet, CSV |

`label_*` columns and `split` are ground truth: never use them as model features.
