#!/usr/bin/env python3
"""
Merge attack-lab runs into one leak-free training table (plan Workstream A, step 1).

Output directory (default datasets/attack-lab/training/<name>/):
  features.parquet  keys (run_id, row_id, pid, recv_ns) + the feature columns of
                    kb-aads/features/schema.py, built ONLY through that schema
  labels.parquet    the same keys + the runner's ground truth and the execution-level
                    split. Labels never appear in features.parquet.
  manifest.json     runs, commit, schema version, row counts, and per-feature
                    PROVENANCE (emitted / default-filled / reconstructed) per run

Honesty rules this script enforces:
  * a feature the run's sensor never emitted is filled with the schema default and
    listed as "absent" in the manifest, not silently treated as measured;
  * tree_* features are RECONSTRUCTED offline by replaying the process_state stream
    through the same rules as kb-control-plane/internal/controlplane/tree.go (subtree
    aggregation), with two approximations (below). They are marked "reconstructed",
    not "emitted";
  * nothing here reads label_* columns while building features.

Approximations in the tree_* replay (events tables carry no process_exit rows and no
start_time_ns): a process stops contributing 120 s after its LAST observed state (kbd:
120 s after its exit, 10 min if never seen to exit); PID reuse is detected only by a
parent change, not by start time. Known hazard, not corrected here: a long-lived parent
(in the lab corpora, the runner process) whose descendants collectively read sensitive
files and connect looks like "both" for as long as it lives.

Usage: build_training_table.py [--out DIR] [RUN_DIR ...]
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "kb-aads"))
from features import schema  # noqa: E402

ZONE_ID = {"SAFE": 0, "SUSPICIOUS": 1, "BORDERLANDS": 2}
DEFAULT_RUNS = ["20261031T183320", "20261031T193756", "20261031T201927"]
TREE_TTL_NS = 120 * 1_000_000_000
TREE_MAX_VISIT = 256
TREE_MAX_DEPTH = 6
KEYS = ["run_id", "row_id", "pid", "recv_ns"]
EMITTED_BY_KBD = {"score", "zone", "is_root", "score_delta", "dim_process", "dim_syscall",
                  "dim_privilege", "dim_file", "dim_network", "dim_memory"}
TREE = ["tree_dim_file", "tree_dim_network", "tree_file_net"]


def replay_tree(ps):
    """ps: process_state rows of ONE run (pid, ppid, recv_ns, dim_file, dim_network),
    in recv_ns order. Returns three arrays aligned with ps: the subtree aggregates of
    tree.go's Update (max file, max network, min of the two). Rules mirror tree.go:
    evidence only goes up; ppid 0 = unknown (the exit snapshot), keep the parent;
    descendants feed ancestors; walk bounded to TREE_MAX_DEPTH levels / TREE_MAX_VISIT nodes."""
    n = len(ps)
    out_f, out_n, out_b = np.zeros(n), np.zeros(n), np.zeros(n)
    nodes = {}      # pid -> [ppid, file, net, last_seen_ns]
    children = {}   # ppid -> set(pid)
    pid_a, ppid_a, t_a = ps.pid.values, ps.ppid.values, ps.recv_ns.values
    f_a, n_a = ps.dim_file.fillna(0.0).values, ps.dim_network.fillna(0.0).values
    for i in range(n):
        pid, ppid, t = int(pid_a[i]), int(ppid_a[i]), int(t_a[i])
        node = nodes.get(pid)
        if node is not None and ppid == 0:
            ppid = node[0]                                   # unknown: keep the parent
        if node is not None and node[0] != ppid:             # reused pid / reparented
            children.get(node[0], set()).discard(pid)
            node = None
        if node is None:
            node = nodes[pid] = [ppid, 0.0, 0.0, t]
        node[1], node[2], node[3] = max(node[1], float(f_a[i])), max(node[2], float(n_a[i])), t
        if ppid > 1:
            children.setdefault(ppid, set()).add(pid)
        f = nt = 0.0
        stack, visited = [(pid, 0)], 0
        while stack and visited < TREE_MAX_VISIT:
            p, d = stack.pop()
            visited += 1
            m = nodes.get(p)
            if m is not None and t - m[3] <= TREE_TTL_NS:
                f, nt = max(f, m[1]), max(nt, m[2])
            if d < TREE_MAX_DEPTH:
                stack.extend((c, d + 1) for c in children.get(p, ()))
        out_f[i], out_n[i], out_b[i] = f, nt, min(f, nt)
    return out_f, out_n, out_b


def build_run(run_dir):
    run_id = os.path.basename(os.path.normpath(run_dir))
    tables = os.path.join(run_dir, "tables")
    ev = pd.read_parquet(os.path.join(tables, "events.parquet"))
    ex = pd.read_parquet(os.path.join(tables, "executions.parquet"))
    ps = ev[ev.event_type == "process_state"].copy().sort_values(["recv_ns", "row_id"]).reset_index(drop=True)

    ps["zone_id"] = ps.zone.map(ZONE_ID).fillna(0).astype(float)
    ps["score_delta"] = ps.groupby("pid").ema_score.diff().fillna(0.0)
    raw = pd.DataFrame({
        "score": ps.ema_score, "zone": ps.zone_id, "is_root": ps.is_root.fillna(0),
        "score_delta": ps.score_delta, "dim_process": ps.dim_process, "dim_syscall": ps.dim_syscall,
        "dim_privilege": ps.dim_privilege, "dim_file": ps.dim_file, "dim_network": ps.dim_network,
        "dim_memory": ps.dim_memory, "telemetry_gap": 0.0})
    for col in ("dest_class", "dest_port", "dest_known"):
        if col in ps.columns:
            raw[col] = ps[col]
    if "ppid" in ps.columns:
        tf, tn, tb = replay_tree(ps)
        raw["tree_dim_file"], raw["tree_dim_network"], raw["tree_file_net"] = tf, tn, tb

    cols = {}
    prov = {}
    for name, lo, hi, default in schema.FEATURES:
        if name in raw:
            v = raw[name].fillna(default).astype(float).values
            prov[name] = "reconstructed" if name in TREE else "emitted"
        else:
            v = np.full(len(raw), default)
            prov[name] = "absent (schema default)"
        cols[name] = np.clip(v, lo, hi)
    feat = pd.DataFrame(cols)
    # the vectorised build must equal the schema's own build_vector
    for i in np.random.RandomState(0).choice(len(raw), min(500, len(raw)), replace=False):
        assert np.allclose(feat.iloc[i].values, schema.build_vector(raw.iloc[i].to_dict())), \
            "feature build diverged from schema.py"

    keys = pd.DataFrame({"run_id": run_id, "row_id": ps.row_id.values, "pid": ps.pid.values, "recv_ns": ps.recv_ns.values})
    features = pd.concat([keys, feat], axis=1)

    starts = ex.sort_values("start_ns")[["start_ns", "split"]].reset_index(drop=True)
    pos = np.clip(np.searchsorted(starts.start_ns.values, ps.recv_ns.values, side="right") - 1, 0, len(starts) - 1)
    exec_split = ex.set_index("execution_id").split
    split = np.where(ps.label_execution_id.notna(), ps.label_execution_id.map(exec_split), starts.split.values[pos])
    labels = pd.concat([keys, pd.DataFrame({
        "execution_id": ps.label_execution_id.values, "scenario": ps.label_scenario.values,
        "family": ps.label_family.values, "kind": ps.label_kind.values,
        "is_attack": ps.label_is_attack.fillna(False).astype(bool).values,
        "attribution": ps.label_attribution.values, "split": split})], axis=1)
    info = {"run_id": run_id, "executions": int(len(ex)), "rows": int(len(ps)),
            "schema_in_events": sorted(ev.feature_schema.dropna().astype(str).unique().tolist()),
            "provenance": prov}
    return features, labels, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("runs", nargs="*")
    a = ap.parse_args()
    base = os.path.join(ROOT, "datasets", "attack-lab")
    runs = [r if os.path.isdir(r) else os.path.join(base, r) for r in (a.runs or DEFAULT_RUNS)]
    out = a.out or os.path.join(base, "training", "v%s-%d-runs" % (schema.SCHEMA_VERSION, len(runs)))
    os.makedirs(out, exist_ok=True)

    feats, labs, infos = [], [], []
    for r in runs:
        f, l, i = build_run(r)
        feats.append(f); labs.append(l); infos.append(i)
        print("%s: %d executions, %d rows" % (i["run_id"], i["executions"], i["rows"]))
    features, labels = pd.concat(feats, ignore_index=True), pd.concat(labs, ignore_index=True)

    assert set(features.columns) == set(KEYS) | set(schema.NAMES), "feature table has unexpected columns"
    assert not (set(features.columns) & schema.FORBIDDEN), "label-like column in features"
    assert not (set(labels.columns) & set(schema.NAMES)), "feature column leaked into labels"
    assert (features[KEYS].values == labels[KEYS].values).all(), "feature/label keys diverged"

    features.to_parquet(os.path.join(out, "features.parquet"), index=False)
    labels.to_parquet(os.path.join(out, "labels.parquet"), index=False)
    try:
        commit = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        commit = None
    manifest = {"schema_version": schema.SCHEMA_VERSION, "feature_names": schema.NAMES, "git_commit": commit,
                "rows": int(len(features)), "runs": infos,
                "split_counts": labels.split.value_counts().to_dict(),
                "kind_counts": labels.kind.value_counts().to_dict(),
                "files": {n: hashlib.sha256(open(os.path.join(out, n), "rb").read()).hexdigest()
                          for n in ("features.parquet", "labels.parquet")}}
    with open(os.path.join(out, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=1)
    print("wrote", out, "rows", len(features))


if __name__ == "__main__":
    main()
