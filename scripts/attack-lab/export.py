#!/usr/bin/env python3
"""
Export an attack-lab run to analysis-ready tables: CSV, Parquet and Excel (.xlsx),
plus the raw files and a data dictionary.

    python3 export.py <run_dir> <out_dir> [--holdout evasion,admin_privileged]

Needs pandas + pyarrow (+ xlsxwriter for .xlsx). Output layout:

    <out_dir>/<run_id>/
        raw/                 events.jsonl, labels.jsonl, manifest.json, actions/
        tables/              events.*, executions.*, kbd_audit.*, splits.csv (csv + parquet + xlsx)
        analysis_report.txt  output of analyze.py
        README.md            data dictionary and usage rules

Columns whose name starts with `label_` (and `split`) are GROUND TRUTH from the
lab runner. They are for targets and metrics only and must never be used as
model features (kb-aads/features/schema.py refuses label-like inputs).
"""
import argparse
import collections
import contextlib
import io
import json
import os
import shutil
import sys
from datetime import datetime, timezone

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze
import labeling

ZONE_ORDER = {"SAFE": 0, "SUSPICIOUS": 1, "BORDERLANDS": 2}
ZONE_NAME = {0: "SAFE", 1: "SUSPICIOUS", 2: "BORDERLANDS"}
DIMS = ["process", "syscall", "privilege", "file", "network", "memory"]


def build_events(real, executions):
    polled = {x["execution_id"]: set(x["pids_polled"]) | {x["root_pid"]} for x in executions}
    rows = []
    by_exec = {}
    for i, (e, hit, _) in enumerate(labeling.label_events(real, executions)):
        md = e["metadata"]
        is_state = e["event_type"] == "process_state"
        row = {
            "row_id": i,
            "recv_ns": e["recv_ns"],
            "recv_utc": datetime.fromtimestamp(e["recv_ns"] / 1e9, tz=timezone.utc).isoformat(timespec="microseconds"),
            "sensor_ts": e["ts"],
            "pid": e["pid"], "ppid": e["ppid"], "comm": e["comm"], "event_type": e["event_type"],
            # kbd puts the EMA score in KBEvent.score_delta (a misnomer); for a
            # zone_transition it is the score at the transition.
            "ema_score": e["score_delta"],
            "zone": md.get("zone") if is_state else md.get("to_zone"),
            "from_zone": md.get("from_zone"), "to_zone": md.get("to_zone"),
            "uid": int(md["uid"]) if md.get("uid") not in (None, "") else None,
            "is_root": (1 if md.get("uid") == "0" else 0) if md.get("uid") not in (None, "") else None,
            "composite": float(md["composite"]) if md.get("composite") else None,
            "event_count": int(md["event_count"]) if md.get("event_count") else None,
            "feature_schema": md.get("feature_schema"),
            "allowlisted": md.get("allowlisted"),
        }
        for d in DIMS:
            row[f"dim_{d}"] = float(md[f"dim_{d}"]) if md.get(f"dim_{d}") else None
        if hit:
            row.update(label_execution_id=hit["execution_id"], label_scenario=hit["scenario"],
                       label_family=hit["family"], label_kind=hit["kind"],
                       label_is_attack=1 if hit["kind"] == "attack" else 0,
                       label_attribution="polled" if e["pid"] in polled[hit["execution_id"]] else "ancestry")
        else:
            row.update(label_execution_id=None, label_scenario=None, label_family=None,
                       label_kind="background", label_is_attack=0, label_attribution="background")
        rows.append(row)
    return pd.DataFrame(rows)


def build_executions(executions, events_df, holdout, seed=7, test_frac=0.4):
    train, test = labeling.split_executions(executions, holdout_families=holdout, test_frac=test_frac, seed=seed)
    split = {x["execution_id"]: "train" for x in train} | {x["execution_id"]: "test" for x in test}
    lab = events_df[events_df.label_execution_id.notna()]
    out = []
    for x in executions:
        es = lab[lab.label_execution_id == x["execution_id"]]
        states = es[es.event_type == "process_state"]
        top = max((ZONE_ORDER.get(z, 0) for z in es.zone.dropna()), default=0)
        audit = collections.Counter(a["action"] for a in x["kbd_audit"])
        out.append({
            "execution_id": x["execution_id"], "scenario": x["scenario"], "family": x["family"], "kind": x["kind"],
            "seed": x["seed"], "root_pid": x["root_pid"],
            "n_pids": len(x["pids"]), "n_pids_polled": len(x["pids_polled"]), "n_pids_from_events": len(x["pids_from_events"]),
            "start_ns": x["start_ns"], "end_ns": x["end_ns"], "duration_s": round((x["end_ns"] - x["start_ns"]) / 1e9, 3),
            "first_malicious_ns": x.get("first_malicious_ns"), "exit_code": x["exit_code"], "timed_out": x["timed_out"],
            "n_events": len(es), "peak_ema_score": float(states.ema_score.max()) if len(states) else 0.0,
            "max_zone": ZONE_NAME[top],
            "n_zone_audit_entries": sum(v for k, v in audit.items() if k.startswith("ZONE_")),
            "n_would_contain": sum(v for k, v in audit.items() if k.startswith("OBSERVE_ONLY_WOULD")),
            "kbd_audit_actions": json.dumps(dict(audit), sort_keys=True),
            "split": split[x["execution_id"]],
        })
    return pd.DataFrame(out)


def build_audit(executions):
    rows = [dict(execution_id=x["execution_id"], **a) for x in executions for a in x["kbd_audit"]]
    return pd.DataFrame(rows, columns=["execution_id", "ts_ns", "action", "subject", "actor", "reason"])


def write_all(df, base):
    df.to_csv(base + ".csv", index=False)
    df.to_parquet(base + ".parquet", index=False, compression="zstd")
    with pd.ExcelWriter(base + ".xlsx", engine="xlsxwriter", engine_kwargs={"options": {"constant_memory": True}}) as w:
        df.to_excel(w, sheet_name=os.path.basename(base), index=False)


README = """# Attack-lab corpus {run_id}

Captured on `{host}` (kernel {kernel}), package {package}, feature schema v{schema}.
`kbd` observe-only (automatic containment OFF): {observe_only}. Sensor exit-state publish: `all`.
{n_exec} executions ({n_events} events, {n_gaps} stream gaps), seed {seed}, {repeats} repeats per scenario.

## Files
- `raw/` is exactly what the runner wrote: `events.jsonl` (telemetry, no labels), `labels.jsonl`
  (one record per execution), `manifest.json`, `actions/<execution>.jsonl` (payload timelines).
- `tables/events.{{csv,parquet,xlsx}}`: one row per `process_state` / `zone_transition` event.
- `tables/executions.*`: one row per execution (scenario, family, kind, window, pids, peak score, max zone, kbd audit).
- `tables/kbd_audit.*`: what `kbd` itself audited for each execution's processes.
- `tables/splits.*`: execution -> train/test. **Proposed example only**: whole executions, families
  `{holdout}` held out entirely, seed 7. Re-split for real experiments.
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
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("out_dir")
    ap.add_argument("--holdout", default="evasion,admin_privileged")
    a = ap.parse_args()
    man = json.load(open(os.path.join(a.run_dir, "manifest.json")))
    executions = labeling.load_jsonl(os.path.join(a.run_dir, "labels.jsonl"))
    events = labeling.load_jsonl(os.path.join(a.run_dir, "events.jsonl"))
    real = [e for e in events if not e.get("gap")]
    root = os.path.join(a.out_dir, man["run_id"])
    raw, tables = os.path.join(root, "raw"), os.path.join(root, "tables")
    os.makedirs(tables, exist_ok=True)
    shutil.copytree(a.run_dir, raw, dirs_exist_ok=True)

    ev_df = build_events(real, executions)
    ex_df = build_executions(executions, ev_df, tuple(a.holdout.split(",")))
    au_df = build_audit(executions)
    sp_df = ex_df[["execution_id", "scenario", "family", "kind", "split"]]
    for name, df in (("events", ev_df), ("executions", ex_df), ("kbd_audit", au_df), ("splits", sp_df)):
        write_all(df, os.path.join(tables, name))
        print(f"wrote {name}: {len(df)} rows")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        analyze.main(a.run_dir)
    open(os.path.join(root, "analysis_report.txt"), "w").write(buf.getvalue())
    open(os.path.join(root, "README.md"), "w").write(README.format(
        run_id=man["run_id"], host=man["host"], kernel=man["kernel"], package=man["package"], schema=man["feature_schema"],
        observe_only="yes" if not man["containment_active"] else "NO (containment was active)",
        n_exec=len(executions), n_events=len(real), n_gaps=man["stream_gaps"], seed=man["seed"], repeats=man["repeats"],
        holdout=a.holdout))
    print("done:", root)


if __name__ == "__main__":
    main()
