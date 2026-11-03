# Attack-lab corpora

One directory per capture run, named by run id (`YYYYMMDDTHHMMSS`).

| Run | Summary |
| --- | --- |
| [`20261031T183320/`](20261031T183320/) | First full corpus: 12 scenarios x 5 repeats = 60 executions, 246,114 events, `kbd` in observe-only mode |
| [`20261103T234334/`](20261103T234334/) | First corpus on the schema-v5 sensor and `kbd` (B1 flags, `PTRACE_USED`, tree features, `dest_known`, per-process counters all emitted live): 18 scenarios x 5 repeats = 90 executions, 162,441 events, 0 stream gaps, `kbd` observe-only. The first capture after the tree feature's scope was frozen. **Captured with the sensor's default exit-state mode (`anomalous`), not `all` as the earlier runs were**, so exit snapshots of benign low-score processes are missing (about half the events of earlier runs): 5 benign executions (3 `benign_database`, 2 `benign_compile`) lasted under a second and produced no events at all. Not comparable with the earlier runs on coverage. The manifest records `lab_infra_pids` (the runner and its ancestors) so analysis can exclude them from background statistics. |

Each run has a `README.md` (data dictionary), `analysis_report.txt`, and `tables/` (Parquet and CSV). Produced by [`../../scripts/attack-lab/runner.py`](../../scripts/attack-lab/runner.py), analysed by `analyze.py`, exported by `export.py`.
