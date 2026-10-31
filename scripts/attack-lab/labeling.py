"""
Ground-truth labeling and leakage-safe splitting for lab captures.

Labels are attached to captured events AFTER the fact from the runner's record
of which processes belonged to which execution. They are never part of the
feature vector (kb-aads/features/schema.py refuses label-like inputs).

Rules:
  * an event belongs to an execution if its pid is in that execution's pid set
    AND it was received inside [start_ns, end_ns + settle_ns];
  * everything else is "background" (execution_id=None), label benign: it is
    the real noise a deployed policy also has to ignore;
  * a window is "telemetry_gap" if a stream gap marker falls inside it.

Splitting is by EXECUTION (never by event or window), optionally holding out
whole scenario FAMILIES, so near-duplicate windows from one run cannot appear
on both sides of the split.
"""
import json
import random

SETTLE_NS = 3_000_000_000


def load_jsonl(path):
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def expand_pids(execution, events, max_rounds=12):
    """Add every process whose ppid chain leads into this execution's tree.

    The runner polls /proc every 50 ms, which misses short-lived children (a
    `sudo cat /etc/shadow` lives ~10 ms). kbd's process_state events carry the
    ppid, so any process whose parent is already in the tree (within the
    execution's time window) belongs to it, and so do ITS children, until
    nothing new is found. Returns a copy with "pids" expanded, "pids_polled"
    (what the runner saw) and "pids_from_events" (what ancestry added).
    zone_transition events carry no ppid and cannot link a process by
    themselves.
    """
    lo, hi = execution["start_ns"], execution["end_ns"] + SETTLE_NS
    win = [e for e in events if not e.get("gap") and lo <= e["recv_ns"] <= hi and e.get("ppid")]
    tree = set(execution["pids"]) | {execution["root_pid"]}
    for _ in range(max_rounds):
        new = {e["pid"] for e in win if e["ppid"] in tree and e["pid"] not in tree and e["pid"] != 0}
        if not new:
            break
        tree |= new
    out = dict(execution)
    out["pids_polled"] = sorted(execution["pids"])
    out["pids"] = sorted(tree)
    out["pids_from_events"] = sorted(tree - set(execution["pids"]) - {execution["root_pid"]})
    return out


def pid_index(executions):
    """pid -> list of (start_ns, end_ns, execution) for fast attribution."""
    idx = {}
    for ex in executions:
        for pid in ex["pids"]:
            idx.setdefault(pid, []).append((ex["start_ns"], ex["end_ns"] + SETTLE_NS, ex))
    return idx


def label_events(events, executions):
    """Yield (event, execution_or_None, is_attack). Gap markers are skipped here."""
    idx = pid_index(executions)
    for ev in events:
        if ev.get("gap"):
            continue
        hit = None
        for start, end, ex in idx.get(ev["pid"], ()):
            if start <= ev["recv_ns"] <= end:
                hit = ex
                break
        yield ev, hit, bool(hit and hit["kind"] == "attack")


def gaps_in(events, start_ns, end_ns):
    return [e for e in events if e.get("gap") and start_ns <= e["recv_ns"] <= end_ns]


def split_executions(executions, holdout_families=(), test_frac=0.3, seed=0):
    """Return (train, test) lists of executions.

    Executions whose family is in holdout_families all go to test (generalisation
    to unseen scenario families). The rest are split per family by whole
    execution so every family keeps train examples when it has more than one run.
    """
    rng = random.Random(seed)
    train, test = [], []
    by_family = {}
    for ex in executions:
        by_family.setdefault(ex["family"], []).append(ex)
    for fam, exs in sorted(by_family.items()):
        if fam in holdout_families:
            test.extend(exs)
            continue
        exs = sorted(exs, key=lambda e: e["execution_id"])
        rng.shuffle(exs)
        n_test = int(round(len(exs) * test_frac)) if len(exs) > 1 else 0
        test.extend(exs[:n_test])
        train.extend(exs[n_test:])
    return train, test


def assert_no_leakage(train, test):
    ids_tr = {e["execution_id"] for e in train}
    ids_te = {e["execution_id"] for e in test}
    both = ids_tr & ids_te
    if both:
        raise AssertionError(f"executions on both sides of the split: {sorted(both)}")
    return True
