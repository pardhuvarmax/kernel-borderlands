#!/usr/bin/env python3
"""
First baseline comparison on an attack-lab corpus (python3 baselines.py <run_dir>/tables).

Compares, with the SAME split and the same features a live deployment could serve:
  * the sensor's FIXED rule engine (zone >= SUSPICIOUS, and zone >= BORDERLANDS)
  * logistic regression and a gradient-boosted tree on schema-v1 features
  * an ablation without zone/score (can a learner beat the rule engine's own output?)

Rules that keep it honest:
  * features = kb-aads/features/schema.py (v1) only; label_* columns are targets, never inputs;
  * the split is by EXECUTION (the corpus' `split` column; whole families held out); background
    rows take the split of the execution running at that time;
  * each model's threshold is chosen on the TRAIN split only, to meet a target false-positive
    rate on benign + background rows; nothing from the test split influences it;
  * the unit of judgement is the EXECUTION (was anything in it flagged?), because row labels are
    noisy (an attack's early helper processes are labelled attack too);
  * n is tiny (a handful of executions per family): 95% Wilson intervals are shown, results are
    descriptive and not a performance claim.
"""
import math
import os
import sys
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "kb-aads")))
from features import schema  # noqa: E402

ZONE_ID = {"SAFE": 0, "SUSPICIOUS": 1, "BORDERLANDS": 2}
TARGET_FPR = 0.001           # on train benign + background rows


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def build_rows(ev, ex):
    ps = ev[ev.event_type == "process_state"].copy().sort_values(["pid", "recv_ns"])
    ps["zone_id"] = ps.zone.map(ZONE_ID).fillna(0).astype(float)
    ps["score_delta"] = ps.groupby("pid").ema_score.diff().fillna(0.0)
    raw = pd.DataFrame({
        "score": ps.ema_score, "zone": ps.zone_id, "is_root": ps.is_root.fillna(0),
        "score_delta": ps.score_delta, "dim_process": ps.dim_process, "dim_syscall": ps.dim_syscall,
        "dim_privilege": ps.dim_privilege, "dim_file": ps.dim_file, "dim_network": ps.dim_network,
        "dim_memory": ps.dim_memory, "telemetry_gap": 0.0})
    X = np.column_stack([np.clip(raw[n].fillna(d).astype(float).values, lo, hi) for n, lo, hi, d in schema.FEATURES])
    # the vectorised build must equal the contract's own build_vector
    for i in np.random.RandomState(0).choice(len(raw), 500, replace=False):
        assert np.allclose(X[i], schema.build_vector(raw.iloc[i].to_dict())), "feature build diverged from schema.py"
    ps = ps.reset_index(drop=True)
    # split: executions by their split; background by the execution running at that time
    starts = ex.sort_values("start_ns")[["start_ns", "split"]].reset_index(drop=True)
    pos = np.searchsorted(starts.start_ns.values, ps.recv_ns.values, side="right") - 1
    pos = np.clip(pos, 0, len(starts) - 1)
    exec_split = ex.set_index("execution_id").split
    ps["row_split"] = np.where(ps.label_execution_id.notna(), ps.label_execution_id.map(exec_split), starts.split.values[pos])
    return ps, X


def pick_threshold(scores_neg_train, target_fpr):
    return float(np.quantile(scores_neg_train, 1 - target_fpr))


def exec_table(ps, flagged, ex):
    rows = []
    for _, x in ex[ex.split == "test"].iterrows():
        m = (ps.label_execution_id == x.execution_id).values
        rows.append((x["family"], x["kind"], bool(flagged[m].any())))
    return pd.DataFrame(rows, columns=["family", "kind", "flagged"])


def main(tables):
    ev = pd.read_parquet(os.path.join(tables, "events.parquet"))
    ex = pd.read_parquet(os.path.join(tables, "executions.parquet"))
    ps, X = build_rows(ev, ex)
    y = ps.label_is_attack.values.astype(int)
    tr = (ps.row_split == "train").values
    te = ~tr
    neg = (ps.label_kind != "attack").values
    print(f"rows={len(ps)}  train={tr.sum()} test={te.sum()}  attack rows: train={int((y[tr]==1).sum())} test={int((y[te]==1).sum())}")
    print(f"test executions: {int((ex.split=='test').sum())}  families held out entirely from train: "
          f"{sorted(set(ex[ex.split=='test'].family) - set(ex[ex.split=='train'].family))}")
    print(f"threshold rule: chosen on TRAIN only so that <= {TARGET_FPR:.1%} of train benign+background rows are flagged\n")

    names = schema.NAMES
    full = list(range(len(names)))
    no_rule_out = [i for i, n in enumerate(names) if n not in ("zone", "score")]
    systems = {}
    systems["fixed rules: zone >= SUSPICIOUS"] = (ps.zone_id.values >= 1)
    systems["fixed rules: zone >= BORDERLANDS"] = (ps.zone_id.values >= 2)
    for label, cols, mk in (
        ("logistic regression (all v1 features)", full, lambda: make_pipeline(StandardScaler(), LogisticRegression(max_iter=300, class_weight="balanced"))),
        ("gradient-boosted tree (all v1 features)", full, lambda: HistGradientBoostingClassifier(max_iter=150, class_weight="balanced", random_state=0)),
        ("gradient-boosted tree (no zone/score)", no_rule_out, lambda: HistGradientBoostingClassifier(max_iter=150, class_weight="balanced", random_state=0)),
    ):
        m = mk().fit(X[tr][:, cols], y[tr])
        s = m.predict_proba(X[:, cols])[:, 1]
        auc = roc_auc_score(y[te], s[te]) if len(set(y[te])) > 1 else float("nan")
        thr = pick_threshold(s[tr & neg], TARGET_FPR)
        systems[f"{label}  [row AUC {auc:.3f}]"] = (s > thr)

    # test-time duration: each execution "owns" the time until the next one starts
    st = ex.sort_values("start_ns").reset_index(drop=True)
    span = (st.start_ns.shift(-1).fillna(ps.recv_ns.max()) - st.start_ns).values
    test_minutes = float(span[(st.split == "test").values].sum()) / 6e10
    fams = sorted(ex[ex.split == "test"].family.unique())
    print(f"{'system':62s} {'attacks flagged':>16s} {'95% CI':>12s} {'benign flagged':>15s} {'95% CI':>12s} {'bg procs/min':>13s}")
    per_family = {}
    for name, flag in systems.items():
        et = exec_table(ps, flag, ex)
        a = et[et.kind == "attack"]; b = et[et.kind == "benign"]
        ka, na, kb, nb = int(a.flagged.sum()), len(a), int(b.flagged.sum()), len(b)
        la, ha = wilson(ka, na); lb, hb = wilson(kb, nb)
        bgm = ps.loc[(ps.label_kind == "background").values & te & flag, "pid"].nunique() / max(test_minutes, 1e-9)
        print(f"{name:62s} {ka:>9d}/{na:<6d} [{la:.2f},{ha:.2f}] {kb:>9d}/{nb:<5d} [{lb:.2f},{hb:.2f}] {bgm:13.2f}")
        per_family[name] = et.groupby(["kind", "family"]).flagged.agg(["sum", "count"])
    print("\n(bg procs/min = distinct background processes flagged per minute of test time: the alert noise on a normal desktop)\nper test family (flagged / executions); attacks first:")
    kinds = sorted({k for t in per_family.values() for k in t.index}, key=lambda t: (t[0] != "attack", t[1]))
    print(f"{'kind':7s}{'family':18s}" + "".join(f"{i+1:>8d}" for i in range(len(systems))))
    for (kind, fam) in kinds:
        cells = []
        for t in per_family.values():
            cells.append(f"{int(t.loc[(kind, fam), 'sum'])}/{int(t.loc[(kind, fam), 'count'])}" if (kind, fam) in t.index else "-")
        print(f"{kind:7s}{fam:18s}" + "".join(f"{c:>8s}" for c in cells))
    print("\nsystems: " + "; ".join(f"{i+1}={n.split('  [')[0]}" for i, n in enumerate(systems)))
    print("\nCaveats: n is tiny (see the intervals), the rule engine and the learned models share the same sensor features,\n"
          "held-out families appear only in test, and nothing here is a claim about performance on other hosts or attacks.")


if __name__ == "__main__":
    main(sys.argv[1])
