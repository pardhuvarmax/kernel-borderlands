#!/usr/bin/env python3
"""
Oracle experiment: can TREE-level evidence separate the matched pairs when no single process can?

    python3 tree_oracle.py <run_dir>/tables

For each execution, aggregate its whole process tree (grouping by the lab's ground-truth
execution id, a stand-in for the ppid-rooted tree a live system could build) and ask:
  * does ANY SINGLE process have both file evidence (dim_file >= 50) and network evidence?
  * does the TREE have both?

The grouping uses ground truth, so this shows what tree-level features could do, not what a
deployed system gets. It is NOT sufficient evidence for a detector. backup_etc and
credential_audit make no network connection; backup_remote and credential_report (added after
the first run of this oracle) read the same secrets AND connect out, which is the case that
tests whether "file plus network in one tree" is a usable rule.
"""
import sys
import pandas as pd

PAIRS = [("exfil_staging", "backup_etc", "backup_remote"), ("credential_dump", "credential_audit", "credential_report")]


def main(tables):
    ev = pd.read_parquet(f"{tables}/events.parquet")
    ex = pd.read_parquet(f"{tables}/executions.parquet")
    ps = ev[(ev.event_type == "process_state") & ev.label_execution_id.notna()]
    agg = ps.groupby("label_execution_id").agg(
        n_procs=("pid", "nunique"), max_dim_file=("dim_file", "max"), max_dim_network=("dim_network", "max")).reset_index()
    pp = ps.groupby(["label_execution_id", "pid"]).agg(f=("dim_file", "max"), n=("dim_network", "max")).reset_index()
    pp["both"] = (pp.f >= 50) & (pp.n > 0)
    agg = agg.merge(pp.groupby("label_execution_id").both.any().rename("single"), on="label_execution_id") \
             .merge(ex[["execution_id", "family", "kind"]], left_on="label_execution_id", right_on="execution_id")
    agg["tree"] = (agg.max_dim_file >= 50) & (agg.max_dim_network > 0)
    print(f"{'family':20s} {'kind':6s} {'n':>2s}  tree has file AND network   single process has both   procs/exec")
    for fams in PAIRS:
        for fam in fams:
            g = agg[agg.family == fam]
            if len(g):
                print(f"{fam:20s} {g.kind.iloc[0]:6s} {len(g):2d}  {int(g.tree.sum()):>14d}/{len(g):<8d}  {int(g.single.sum()):>14d}/{len(g):<6d}  {g.n_procs.mean():8.1f}")
        print()
    print("Caveats: oracle grouping (ground-truth execution id); 5 executions per family; backup_remote and\n"
          "credential_report are benign work that reads secrets and uses the network.")


if __name__ == "__main__":
    main(sys.argv[1])
