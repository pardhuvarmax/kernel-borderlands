# Attack-lab corpus 20261031T183320

Captured on `UbuntuVM-eBPF` (kernel 6.8.0-139-generic), package 1.1.0, feature schema v1.
`kbd` observe-only (automatic containment OFF): yes. Sensor exit-state publish: `all`.
60 executions (246114 events, 0 stream gaps), seed 101, 5 repeats per scenario.

## Files
- `raw/` is exactly what the runner wrote: `events.jsonl` (telemetry, no labels), `labels.jsonl`
  (one record per execution), `manifest.json`, `actions/<execution>.jsonl` (payload timelines).
- `tables/events.{csv,parquet,xlsx}`: one row per `process_state` / `zone_transition` event.
- `tables/executions.*`: one row per execution (scenario, family, kind, window, pids, peak score, max zone, kbd audit).
- `tables/kbd_audit.*`: what `kbd` itself audited for each execution's processes.
- `tables/splits.*`: execution -> train/test. **Proposed example only**: whole executions, families
  `evasion,admin_privileged` held out entirely, seed 7. Re-split for real experiments.
- `analysis_report.txt`: the descriptive report (`analyze.py`).

## events columns
Telemetry (schema v1; these are the only columns a model may use):
`recv_ns`, `recv_utc`, `sensor_ts`, `pid`, `ppid`, `comm`, `event_type`, `ema_score`, `zone`, `uid`, `is_root`,
`composite`, `event_count`, `dim_process`, `dim_syscall`, `dim_privilege`, `dim_file`, `dim_network`, `dim_memory`,
`feature_schema`. For `zone_transition` rows also `from_zone`, `to_zone`; `allowlisted` is set by kbd when an
allowlisted, verified system binary was exempted from automatic containment.
`ema_score` is kbd's `KBEvent.score_delta` (a misnomer: it carries the EMA score).
`recv_ns` is wall-clock time the event was received; `sensor_ts` is the sensor's own clock (not wall time).

**GROUND TRUTH (targets and metrics only, never features):** `label_execution_id`, `label_scenario`, `label_family`,
`label_kind` (`attack` / `benign` / `background`), `label_is_attack`, `label_attribution`
(`polled` = pid seen by the runner, `ancestry` = linked through the ppid chain, `background` = unattributed).

## Rules for use
- Split by EXECUTION (never by event or window) and hold out whole scenario families.
- `background` rows are real desktop activity that no scenario produced; they are benign noise, not an execution.
- Counts per family are small (5 per scenario): treat results as descriptive, not as performance claims.
- Known limitations: only processes `kbd` forwards appear (the sensor syncs state every 20 events, on zone
  changes, and now on exit); the loopback-only payloads are simulations of behaviour, not real exploits.
