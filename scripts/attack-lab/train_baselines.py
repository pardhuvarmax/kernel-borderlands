#!/usr/bin/env python3
"""
Baselines on a merged training table (plan Workstream A, step 2-3).

    train_baselines.py TABLE_DIR [--out report.txt]

TABLE_DIR holds features.parquet / labels.parquet / manifest.json from build_training_table.py.

Discipline (the plan's ground rules):
  * labels are targets only; features come from kb-aads/features/schema.py names;
  * every fit and every threshold uses the TRAIN split only; thresholds are set at a fixed
    background-noise budget on train negatives (benign + background rows);
  * hyperparameters are fixed in this file, nothing is tuned, so the TEST split is opened exactly
    once, in the last section, for the fixed list of systems below;
  * leave-one-family-out uses train-split executions only (it never touches test);
  * every proportion carries a 95% Wilson interval and its sample size.

Per-execution rule: an execution is flagged if ANY of its rows scores at or above the threshold.
Caveats, not fixed here: feature columns a run's sensor never emitted hold the schema default; the
old runs lack the v5 counters and dest_*; tree_* are reconstructed for the old runs.
"""
import argparse
import math
import os
import sys
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "kb-aads")))
from features import schema  # noqa: E402

TARGET_FPR = 0.001
MAX_NEG_FIT = 150_000
V1 = ["score", "zone", "is_root", "score_delta", "dim_process", "dim_syscall", "dim_privilege",
      "dim_file", "dim_network", "dim_memory", "telemetry_gap"]
TREE = ["tree_dim_file", "tree_dim_network", "tree_file_net"]
SETS = {"v1": V1, "v1+tree": V1 + TREE, "all": list(schema.NAMES)}
NO_RULE = lambda cols: [c for c in cols if c not in ("zone", "score")]  # noqa: E731


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def fmt(k, n):
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({lo:.0%}-{hi:.0%})"


def make(kind):
    if kind == "lr":
        return make_pipeline(StandardScaler(), LogisticRegression(max_iter=300, class_weight="balanced"))
    return HistGradientBoostingClassifier(max_iter=150, class_weight="balanced", random_state=0)


def fit_threshold(df, cols, kind):
    """Fit on df (train rows only) and return (model, threshold at TARGET_FPR on ALL train negatives)."""
    pos = df[df.is_pos]
    neg = df[~df.is_pos]
    fit_neg = neg.sample(min(len(neg), MAX_NEG_FIT), random_state=0)
    fit = pd.concat([pos, fit_neg])
    m = make(kind).fit(fit[cols].values, fit.is_pos.values.astype(int))
    thr = float(np.quantile(m.predict_proba(neg[cols].values)[:, 1], 1 - TARGET_FPR))
    return m, thr


def exec_flags(df, flagged_mask):
    """Per execution: any row flagged. Returns (attack_k, attack_n, benign_k, benign_n)."""
    e = df[df.execution_id.notna()].assign(f=flagged_mask[df.execution_id.notna().values])
    g = e.groupby(["kind", "execution_id"]).f.max().reset_index()
    a, b = g[g.kind == "attack"], g[g.kind == "benign"]
    return int(a.f.sum()), len(a), int(b.f.sum()), len(b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("table")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    f = pd.read_parquet(os.path.join(a.table, "features.parquet"))
    l = pd.read_parquet(os.path.join(a.table, "labels.parquet"))
    d = f.merge(l.drop(columns=["pid", "recv_ns"]), on=["run_id", "row_id"])
    d["is_pos"] = d.kind.eq("attack") & d.is_attack
    tr, te = d[d.split == "train"].reset_index(drop=True), d[d.split == "test"].reset_index(drop=True)
    out = []
    P = out.append

    P(f"table: {a.table}\nrows {len(d)}  train {len(tr)}  test {len(te)}  executions {d.execution_id.nunique()}")
    ex = d[d.execution_id.notna()].drop_duplicates("execution_id")
    P("executions with rows, by split/kind: " + str(ex.groupby(["split", "kind"]).size().to_dict()))
    P(f"threshold rule: chosen on TRAIN only so that <= {TARGET_FPR:.1%} of train benign+background rows are flagged\n")

    # ---- everything below is fixed in advance: no tuning, the test split is scored once ----
    systems = []
    systems.append(("fixed rules: zone >= SUSPICIOUS", "-", lambda df: (df.zone >= 1).values))
    systems.append(("fixed rules: zone >= BORDERLANDS", "-", lambda df: (df.zone >= 2).values))
    fitted = {}
    for sname, cols in SETS.items():
        for kind, label in (("lr", "logistic regression"), ("gbt", "gradient-boosted tree")):
            m, thr = fit_threshold(tr, cols, kind)
            fitted[(label, sname)] = (m, thr, cols)
            systems.append((label, sname, (lambda m_, t_, c_: lambda df: m_.predict_proba(df[c_].values)[:, 1] >= t_)(m, thr, cols)))
        cols2 = NO_RULE(cols)
        m, thr = fit_threshold(tr, cols2, "gbt")
        systems.append(("gradient-boosted tree, no zone/score", sname,
                        (lambda m_, t_, c_: lambda df: m_.predict_proba(df[c_].values)[:, 1] >= t_)(m, thr, cols2)))

    P("=== TEST split (opened once): per-execution recall and false-positive rate, 95% Wilson intervals ===")
    P(f"{'system':42} {'features':8} {'attack flagged':20} {'benign flagged':20} bg rows flagged")
    bgm = te.execution_id.isna().values
    for name, fs, fn in systems:
        fl = np.asarray(fn(te))
        ak, an, bk, bn = exec_flags(te, fl)
        P(f"{name:42} {fs:8} {fmt(ak, an):20} {fmt(bk, bn):20} {fl[bgm].sum()}/{bgm.sum()}")

    P("\n=== Leave-one-family-out (TRAIN split only; never touches test) ===")
    P("train on train-split executions of every other family, threshold on their negatives, report recall on the held-out family")
    fams = sorted(tr[tr.kind == "attack"].family.dropna().unique())
    P(f"{'held-out family':20} " + "  ".join(f"{k:>26}" for k in ("rules >= SUSPICIOUS", "LR (v1+tree)", "GBT (v1+tree)", "GBT (all)")))
    for fam in fams:
        sub = tr[~((tr.family == fam) & tr.execution_id.notna())]
        held = tr[(tr.family == fam) & tr.execution_id.notna()]
        row = []
        n_ex = held.execution_id.nunique()
        k = int(held.assign(f=(held.zone >= 1).values).groupby("execution_id").f.max().sum())
        row.append(fmt(k, n_ex))
        for kind, sname in (("lr", "v1+tree"), ("gbt", "v1+tree"), ("gbt", "all")):
            cols = SETS[sname]
            m, thr = fit_threshold(sub, cols, kind)
            fl = m.predict_proba(held[cols].values)[:, 1] >= thr
            row.append(fmt(int(held.assign(f=fl).groupby("execution_id").f.max().sum()), n_ex))
        P(f"{fam:20} " + "  ".join(f"{x:>26}" for x in row))

    P("\nCaveats: tiny n (see the intervals); the rules and the learned models share the same sensor features;"
      " held-out families appear only in test; feature columns a run never emitted hold schema defaults;"
      " tree_* are reconstructed for the three older runs; nothing here is a claim about other hosts or attacks.")
    text = "\n".join(out)
    print(text)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(text + "\n")


if __name__ == "__main__":
    main()
