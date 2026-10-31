# Attack-lab corpora

One directory per capture run, named by run id (`YYYYMMDDTHHMMSS`).

| Run | Summary |
| --- | --- |
| [`20261031T183320/`](20261031T183320/) | First full corpus: 12 scenarios x 5 repeats = 60 executions, 246,114 events, `kbd` in observe-only mode |

Each run has a `README.md` (data dictionary), `analysis_report.txt`, and `tables/` (Parquet and CSV). Produced by [`../../scripts/attack-lab/runner.py`](../../scripts/attack-lab/runner.py), analysed by `analyze.py`, exported by `export.py`.
