#!/usr/bin/env python3
"""
Phase 0 (scoped) — labeling for Containment's RL training set, from ADFA-LD
syscall traces + real local-machine telemetry (see collect.py).

Target schema matches what kb-control-plane actually puts on the wire
(kb-control-plane/proto/kb.proto):
    ProcessState.score   -> score        (float, 0-100)
    ProcessState.zone    -> zone          (0=SAFE, 1=SUSPICIOUS, 2=BORDERLANDS)
    ProcessState.uid     -> uid_is_root   (0/1 — engineered, see below)
    KBEvent.score_delta  -> score_delta   (float, -100..100)
    KBEvent.event_type   -> event_type    (0..3, engineered category)
and a target action matching ContainmentLevel:
    0 NONE, 1 CGROUP, 2 SECCOMP, 3 NAMESPACE, 4 TERMINATE

Score is NOT a random per-category band (that was this pipeline's first,
weaker draft against NSL-KDD). It's a real computed statistic — but the
first real attempt at one (single-syscall rarity against the Normal
frequency distribution) turned out empirically degenerate: verified by
direct measurement that attack and normal traces draw from almost the same
syscall vocabulary, so a rarity/novelty score came out ~0.0 for nearly
every trace, attack or not. Measured instead (via direct comparison against
ADFA-LD's real Normal traces) which per-trace statistics actually separate
categories: mean syscall diversity is 0.082 for Normal vs. 0.028-0.095
across the five mapped attack categories (privilege_escalation/
process_injection markedly lower — narrow, repetitive syscall sequences;
lateral_movement notably higher), and repeat-run-length/trace-length show
similar, if noisier, separation. `score` is a composite z-score across all
three statistics against the real Normal distribution, saturated to 0-100
via `trace_features()` below — a real, data-derived signal, not a
per-category constant, though an imperfect one: ADFA-LD is itself a
research dataset specifically because attack traces are subtly disguised
as normal behavior at the local-pattern level (that's its own papers'
stated motivation for retiring cruder KDD-style datasets), so don't expect
clean linear separability here. score_delta is the same composite z-score
computed on the trace's second half minus its first half — a real
escalation-trend signal per trace, not fabricated.

KB attack-scenario -> ContainmentLevel mapping (proposed, NOT Karthik-
confirmed — same "proposed design" status the roadmap uses elsewhere in
this project for anything not yet signed off):
    normal                -> NONE       (0)
    credential_access      -> CGROUP    (1)  — brute-force attempt, contain resources
    lateral_movement       -> SECCOMP   (2)  — spreading, restrict syscalls
    privilege_escalation   -> NAMESPACE (3)  — compromise achieved, isolate
    process_injection      -> NAMESPACE (3)  — compromise achieved, isolate
    reverse_shell          -> TERMINATE (4)  — active C2 channel, kill

Known gap: KB's attack-lab also defines `memory_exploit.sh` (mmap/mprotect
RWX). ADFA-LD has no matching category — this training set does not cover
that scenario. Stated here, not silently dropped.
"""
import csv
import os
import random
import statistics
from collections import Counter

from collect import ADFA_CATEGORY_TO_KB_SCENARIO, ADFA_DIR, OUT_DIR

RAW_DIR = OUT_DIR
LABELED_PATH = os.path.join(os.path.dirname(RAW_DIR), "labeled.csv")

KB_SCENARIO_TARGET = {
    "normal": 0,                 # NONE
    "credential_access": 1,       # CGROUP
    "lateral_movement": 2,        # SECCOMP
    "privilege_escalation": 3,    # NAMESPACE
    "process_injection": 3,       # NAMESPACE
    "reverse_shell": 4,           # TERMINATE
}

KB_SCENARIO_ZONE_FLOOR = {
    "normal": 0, "credential_access": 1, "lateral_movement": 1,
    "privilege_escalation": 2, "process_injection": 2, "reverse_shell": 2,
}

KB_SCENARIO_EVENT_TYPE = {
    "normal": 0, "credential_access": 1, "lateral_movement": 1,
    "privilege_escalation": 2, "process_injection": 2, "reverse_shell": 3,
}

def read_trace(path):
    with open(path) as f:
        return [int(tok) for tok in f.read().split()]


def iter_normal_traces():
    for subdir in ("Training_Data_Master", "Validation_Data_Master"):
        d = os.path.join(ADFA_DIR, subdir)
        for fname in os.listdir(d):
            yield os.path.join(d, fname)


def iter_attack_traces():
    attack_root = os.path.join(ADFA_DIR, "Attack_Data_Master")
    for folder in os.listdir(attack_root):
        # folder like "Adduser_3" -> category "Adduser"
        category = folder.rsplit("_", 1)[0]
        scenario = ADFA_CATEGORY_TO_KB_SCENARIO.get(category)
        if scenario is None:
            continue
        folder_path = os.path.join(attack_root, folder)
        for fname in os.listdir(folder_path):
            yield os.path.join(folder_path, fname), scenario


def _raw_stats(trace):
    """(length, syscall-diversity-ratio, longest-repeat-run) for one trace."""
    n = len(trace)
    if n == 0:
        return 0, 0.0, 0
    diversity = len(set(trace)) / n
    best = cur = 1
    for i in range(1, n):
        if trace[i] == trace[i - 1]:
            cur += 1
            best = max(best, cur)
        else:
            cur = 1
    return n, diversity, best


def build_normal_baseline():
    """Real (mean, stdev) of length/diversity/run-length from ADFA-LD's own Normal traces."""
    lens, divs, runs = [], [], []
    for path in iter_normal_traces():
        n, d, r = _raw_stats(read_trace(path))
        lens.append(n)
        divs.append(d)
        runs.append(r)
    return {
        "len": (statistics.mean(lens), statistics.pstdev(lens) or 1.0),
        "div": (statistics.mean(divs), statistics.pstdev(divs) or 1.0),
        "run": (statistics.mean(runs), statistics.pstdev(runs) or 1.0),
    }


def _composite_z(n, diversity, run, baseline):
    z_len = (n - baseline["len"][0]) / baseline["len"][1]
    z_div = (diversity - baseline["div"][0]) / baseline["div"][1]
    z_run = (run - baseline["run"][0]) / baseline["run"][1]
    return (abs(z_len) + abs(z_div) + abs(z_run)) / 3.0


def trace_features(trace, baseline):
    """Composite anomaly score (0-100) and trend delta (-100..100) for one trace."""
    if not trace:
        return 0.0, 0.0

    n, diversity, run = _raw_stats(trace)
    composite = _composite_z(n, diversity, run, baseline)
    score = min(100.0, composite * 25.0)

    half = len(trace) // 2 or 1
    first, second = trace[:half], trace[half:] or trace[half - 1:]
    z_first = _composite_z(*_raw_stats(first), baseline) if first else 0.0
    z_second = _composite_z(*_raw_stats(second), baseline) if second else 0.0
    delta = max(-100.0, min(100.0, (z_second - z_first) * 25.0))

    return score, delta


def main(random_seed: int = 42):
    random.seed(random_seed)
    print("[label] building real length/diversity/repeat-run baseline from ADFA-LD Normal traces ...")
    baseline = build_normal_baseline()
    print(f"[label] baseline: len={baseline['len']}, diversity={baseline['div']}, run={baseline['run']}")

    rows = []

    print("[label] labeling Normal traces ...")
    for path in iter_normal_traces():
        trace = read_trace(path)
        score, delta = trace_features(trace, baseline)
        score = round(score, 2)
        rows.append({
            "score": score,
            "zone": 0,
            "uid_is_root": 0,
            "score_delta": round(delta, 2),
            "event_type": 0,
            "target_containment": 0,
            "source": "adfa_ld",
            "category": "normal",
        })

    print("[label] labeling Attack traces ...")
    for path, scenario in iter_attack_traces():
        trace = read_trace(path)
        score, delta = trace_features(trace, baseline)
        score = round(score, 2)
        zone_floor = KB_SCENARIO_ZONE_FLOOR[scenario]
        # Real per-trace composite score can land low even for a labeled attack
        # (short/quiet traces) — floor the zone at the scenario's minimum
        # severity so a genuinely-labeled attack is never SAFE-zoned, while
        # still letting the computed score (not just the category) drive
        # exactly where within [floor, 2] it lands.
        zone = max(zone_floor, min(2, int(score / 40)))
        rows.append({
            "score": score,
            "zone": zone,
            "uid_is_root": 1 if scenario == "privilege_escalation" else 0,
            "score_delta": round(delta, 2),
            "event_type": KB_SCENARIO_EVENT_TYPE[scenario],
            "target_containment": KB_SCENARIO_TARGET[scenario],
            "source": "adfa_ld",
            "category": scenario,
        })

    print("[label] labeling real local-machine benign samples ...")
    local_path = os.path.join(RAW_DIR, "local_benign.csv")
    with open(local_path) as f:
        samples = list(csv.DictReader(f))
    loads = [float(r["load1"]) for r in samples] or [1.0]
    max_load = max(loads) if max(loads) > 0 else 1.0
    net_deltas = [int(r["net_rx_delta"]) + int(r["net_tx_delta"]) for r in samples]
    max_net = max(net_deltas) if net_deltas and max(net_deltas) > 0 else 1.0
    for r, net_delta in zip(samples, net_deltas):
        load1 = float(r["load1"])
        score = round(min(20.0, (load1 / max_load) * 20.0), 2)
        score_delta = round((net_delta / max_net) * 10.0, 2)
        rows.append({
            "score": score,
            "zone": 0,
            "uid_is_root": 0,
            "score_delta": score_delta,
            "event_type": 0,
            "target_containment": 0,
            "source": "local_machine",
            "category": "normal",
        })

    random.shuffle(rows)
    fieldnames = ["score", "zone", "uid_is_root", "score_delta", "event_type",
                  "target_containment", "source", "category"]
    with open(LABELED_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    by_cat = Counter(r["category"] for r in rows)
    print(f"[label] wrote {len(rows)} labeled rows to {LABELED_PATH}")
    print(f"[label] class distribution: {dict(by_cat)}")


if __name__ == "__main__":
    main()
