#!/usr/bin/env python3
"""
Descriptive report for an attack-lab corpus (python3 analyze.py <run_dir>).

Per scenario FAMILY: executions, attributed events, the highest zone reached by
any attributed process, what the FIXED rule engine would have done, and the
share of executions flagged, with 95% Wilson intervals (n is small: treat as
descriptive, not as a performance claim). Labels are used here for REPORTING
only; they are never features.
"""
import collections
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labeling

ZONE_ORDER = {"SAFE": 0, "SUSPICIOUS": 1, "BORDERLANDS": 2}


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def main(run):
    man = json.load(open(os.path.join(run, "manifest.json")))
    ex = labeling.load_jsonl(os.path.join(run, "labels.jsonl"))
    ev = labeling.load_jsonl(os.path.join(run, "events.jsonl"))
    real = [e for e in ev if not e.get("gap")]
    per = collections.defaultdict(list)
    n_attr = 0
    for e, hit, _ in labeling.label_events(real, ex):
        if hit:
            per[hit["execution_id"]].append(e)
            n_attr += 1
    print(f"run {man['run_id']}  host={man['host']}  kernel={man['kernel']}  package={man['package']}  schema={man['feature_schema']}")
    print(f"containment_active={man['containment_active']}  audit_export_ok={man.get('audit_export_ok')}  stream_gaps={man['stream_gaps']}")
    print(f"events={len(real)}  attributed={n_attr} ({100*n_attr/len(real):.1f}%; the rest is background desktop activity)")
    zero = [x["execution_id"] for x in ex if not per.get(x["execution_id"])]
    print(f"executions={len(ex)}  with zero attributed events: {len(zero)} {zero[:5]}")

    fam = collections.defaultdict(list)
    for x in ex:
        fam[(x["kind"], x["family"])].append(x)
    print()
    print(f"{'kind':6s} {'family':20s} {'n':>2s} {'events/exec':>11s} {'peak score':>10s} {'reached SUSP+':>14s} {'95% CI':>13s} {'reached BORD':>12s} {'would-contain':>13s}")
    rows = []
    for (kind, family), xs in sorted(fam.items()):
        evs = [len(per.get(x["execution_id"], [])) for x in xs]
        peaks, susp, bord, would = [], 0, 0, 0
        for x in xs:
            es = per.get(x["execution_id"], [])
            sc = [e["score_delta"] for e in es if e["event_type"] == "process_state"]
            peaks.append(max(sc) if sc else 0.0)
            zones = [(e["metadata"].get("zone") if e["event_type"] == "process_state" else e["metadata"].get("to_zone")) for e in es]
            top = max((ZONE_ORDER.get(z, 0) for z in zones), default=0)
            susp += top >= 1
            bord += top >= 2
            would += any(a["action"].startswith("OBSERVE_ONLY_WOULD") for a in x["kbd_audit"])
        lo, hi = wilson(susp, len(xs))
        rows.append((kind, family, len(xs), susp, bord, would))
        print(f"{kind:6s} {family:20s} {len(xs):2d} {sum(evs)/len(xs):11.1f} {sum(peaks)/len(xs):10.1f} {susp:>9d}/{len(xs):<4d} [{lo:.2f},{hi:.2f}] {bord:>8d}/{len(xs):<3d} {would:>9d}/{len(xs)}")
    atk = [r for r in rows if r[0] == "attack"]; ben = [r for r in rows if r[0] == "benign"]
    na, sa = sum(r[2] for r in atk), sum(r[3] for r in atk)
    nb, sb = sum(r[2] for r in ben), sum(r[3] for r in ben)
    print()
    la, ha = wilson(sa, na); lb, hb = wilson(sb, nb)
    print(f"fixed rule engine, executions flagged SUSPICIOUS or higher: attacks {sa}/{na} ({100*sa/na:.0f}%, CI [{la:.2f},{ha:.2f}]); benign {sb}/{nb} ({100*sb/nb:.0f}%, CI [{lb:.2f},{hb:.2f}])")
    # time to first kbd zone audit for attack executions
    ttd = []
    for x in ex:
        if x["kind"] == "attack" and x.get("first_malicious_ns"):
            z = [a["ts_ns"] for a in x["kbd_audit"] if a["action"].startswith("ZONE_")]
            if z:
                ttd.append((min(z) - x["first_malicious_ns"]) / 1e6)
    if ttd:
        ttd.sort()
        print(f"time from first malicious action to first kbd zone audit (flagged attacks, n={len(ttd)}): median {ttd[len(ttd)//2]:.0f} ms, max {ttd[-1]:.0f} ms")


if __name__ == "__main__":
    main(sys.argv[1])
