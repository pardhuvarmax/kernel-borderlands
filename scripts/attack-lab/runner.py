#!/usr/bin/env python3
"""
KB attack-lab scenario runner.

Runs benign workloads and simulated attacks one execution at a time against a
live KB stack (kbd + kbd_sensor) while recording kbd's event feed, and writes a
corpus with ground truth kept SEPARATE from the telemetry:

    <out>/<run_id>/
        events.jsonl     what kbd emitted (+ {"gap":...} markers), no labels
        labels.jsonl     one record per execution: scenario, family, kind,
                         root pid, every pid seen in its tree, wall-clock
                         window, first malicious action time
        actions/<id>.jsonl   the payload's own action log (ground truth timeline)
        manifest.json    host, kernel, package/sensor version, schema version,
                         seed, kbd stats before/after, sensor summary lines

Usage (as an ordinary user in the `kb` group, NOT root; payloads that need
privilege use `sudo -n`):

    runner.py --list
    runner.py --ack-isolated --scenarios all --repeats 3 --seed 1 --out corpus
    runner.py --ack-isolated --scenarios credential_access,benign_admin_privileged --repeats 1 --dry-run

THIS RUNS REAL SIMULATED ATTACK BEHAVIOUR. Only on an isolated lab VM
(--ack-isolated is required and is your statement that it is one).
"""
import argparse
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from payloads import SCENARIOS  # noqa: E402

SCHEMA_VERSION = "1"  # kb-aads/features/schema.py
POLL_S = 0.05


def children_of(root_pid, known):
    """Pids whose parent chain reaches root_pid, found by scanning /proc."""
    found = set()
    parents = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat") as f:
                stat = f.read()
            parents[int(name)] = int(stat.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
    tree = {root_pid} | known
    changed = True
    while changed:
        changed = False
        for pid, ppid in parents.items():
            if ppid in tree and pid not in tree:
                tree.add(pid)
                found.add(pid)
                changed = True
    return found


class TreeWatcher(threading.Thread):
    """Polls /proc while an execution runs so short-lived children are caught."""

    def __init__(self, root_pid):
        super().__init__(daemon=True)
        self.root = root_pid
        self.pids = {root_pid}
        self._halt = threading.Event()

    def run(self):
        while not self._halt.is_set():
            self.pids |= children_of(self.root, self.pids)
            time.sleep(POLL_S)

    def stop(self):
        self._halt.set()
        self.join(timeout=2)


def first_malicious_ns(actions_path):
    try:
        with open(actions_path) as f:
            for line in f:
                rec = json.loads(line)
                if rec.get("malicious"):
                    return rec["ts_ns"]
    except OSError:
        pass
    return None


def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def kbd_stats(socket_path):
    try:
        from comms.grpc_client import ControlPlaneClient
        c = ControlPlaneClient(socket_path=socket_path)
        import kb_pb2
        r = c.stub.GetSystemStats(kb_pb2.Empty())
        c.close()
        return {"events_per_second": r.events_per_second, "active_processes": r.active_processes}
    except Exception as e:  # noqa: BLE001
        return {"error": type(e).__name__}


def kbd_observe_only():
    """True/False if kbd's service environment says KB_OBSERVE_ONLY=1, None if unknown."""
    out = sh(["systemctl", "show", "kbd", "-p", "Environment", "--value"])
    if not out and not shutil.which("systemctl"):
        return None
    return "KB_OBSERVE_ONLY=1" in out.split()


def audit_entries(socket_path):
    """kbd's audit log via the shipped `kbctl audit export` (the Python gRPC
    stubs in kb-aads/comms predate that RPC). None if it cannot be read."""
    try:
        out = subprocess.run(["kbctl", "audit", "export", "--socket", socket_path],
                             capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            return None
        return [{"ts_ns": int(e["ts_ns"]), "action": e["action"], "subject": e.get("subject", ""),
                 "actor": e.get("actor", ""), "reason": e.get("reason", "")} for e in json.loads(out.stdout)]
    except Exception:  # noqa: BLE001
        return None


def audit_for_execution(entries, ex, margin_ns=1_000_000_000):
    """What kbd itself did about this execution's processes: zone changes and
    any containment (applied, or OBSERVE_ONLY_WOULD_*), by pid and time window.
    Stored with the labels so a policy is never trained on 'attacks that were
    already being contained' without that being visible."""
    import re
    pids = set(ex["pids"])
    lo, hi = ex["start_ns"] - margin_ns, ex["end_ns"] + 3_000_000_000
    out = []
    for e in entries or ():
        m = re.search(r"\bpid=(\d+)", e["subject"])
        if m and int(m.group(1)) in pids and lo <= e["ts_ns"] <= hi:
            out.append(e)
    return out


def build_plan(names, repeats, seed):
    rng = random.Random(seed)
    plan = []
    for name in names:
        for i in range(repeats):
            plan.append((name, i, rng.randint(0, 2**31 - 1)))
    rng.shuffle(plan)  # order must not correlate with scenario (drift, cache warmth)
    return plan


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--ack-isolated", action="store_true",
                    help="I confirm this is an isolated lab VM (required to run anything)")
    ap.add_argument("--scenarios", default="all")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--gap", type=float, default=6.0, help="seconds between executions")
    ap.add_argument("--timeout", type=float, default=180.0, help="per-execution hard limit")
    ap.add_argument("--out", default="corpus")
    ap.add_argument("--socket", default="/run/kb/kba.sock")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--allow-containment", action="store_true",
                    help="record even though kbd applies automatic containment (distorts the data: "
                         "attacks get throttled/killed mid-run). Off by default.")
    a = ap.parse_args()

    if a.list:
        for n, (kind, fam, _, secs) in sorted(SCENARIOS.items()):
            print(f"{n:26s} {kind:7s} family={fam:20s} ~{secs}s")
        return 0

    names = sorted(SCENARIOS) if a.scenarios == "all" else a.scenarios.split(",")
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        print(f"unknown scenarios: {unknown}", file=sys.stderr)
        return 2
    plan = build_plan(names, a.repeats, a.seed)
    est = sum(SCENARIOS[n][3] + a.gap + 3 for n, _, _ in plan)
    print(f"{len(plan)} executions, ~{est / 60:.1f} min")
    if a.dry_run:
        for n, i, s in plan:
            print(f"  {n} #{i} seed={s}")
        return 0

    if not a.ack_isolated:
        print("refusing to run: pass --ack-isolated to confirm this is an isolated lab VM", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        print("refusing to run as root: run as an ordinary user in the kb group "
              "(payloads use `sudo -n` where they need privilege)", file=sys.stderr)
        return 2

    observe_only = kbd_observe_only()
    if observe_only is not True and not a.allow_containment:
        print("refusing to run: kbd is not in observe-only mode"
              + (" (could not determine it)" if observe_only is None else "") + ".\n"
              "Automatic containment (BORDERLANDS throttle, auto_terminate) would truncate the attacks and\n"
              "teach the model attacks that were already being contained. Set it for the capture:\n"
              "    sudo systemctl edit kbd     # [Service]  Environment=KB_OBSERVE_ONLY=1\n"
              "    sudo systemctl restart kbd\n"
              "and remove the override afterwards. Or pass --allow-containment to record anyway "
              "(containment is then logged per execution and the manifest says so).", file=sys.stderr)
        return 2

    from capture import Capture
    run_id = time.strftime("%Y%m%dT%H%M%S")
    root = os.path.join(a.out, run_id)
    os.makedirs(os.path.join(root, "actions"))
    events_path = os.path.join(root, "events.jsonl")
    cap = Capture(events_path, a.socket)
    try:
        cap.start()
    except RuntimeError as e:
        print(f"refusing to run: {e}", file=sys.stderr)
        shutil.rmtree(root, ignore_errors=True)
        return 2

    manifest = {
        "run_id": run_id, "host": platform.node(), "kernel": platform.release(),
        "package": sh(["dpkg-query", "-W", "-f=${Version}", "kernel-borderlands"]) or sh(["pacman", "-Q", "kernel-borderlands"]),
        "feature_schema": SCHEMA_VERSION, "seed": a.seed, "repeats": a.repeats,
        "scenarios": names, "kbd_stats_before": kbd_stats(a.socket),
        "containment_active": observe_only is not True,
        "started_wall_ns": time.time_ns(),
    }
    executions = []
    scratch = tempfile.mkdtemp(prefix="kblab-")
    try:
        for n, (name, rep, seed) in enumerate(plan):
            kind, family, _, _ = SCENARIOS[name]
            exec_id = f"{run_id}-{name}-{rep:03d}"
            actions = os.path.join(root, "actions", f"{exec_id}.jsonl")
            wd = os.path.join(scratch, exec_id)
            print(f"[{n + 1}/{len(plan)}] {exec_id} ({kind})", flush=True)
            start_ns = time.time_ns()
            proc = subprocess.Popen(
                [sys.executable, os.path.join(HERE, "payloads.py"), name, "--workdir", wd,
                 "--actions", actions, "--seed", str(seed)],
                start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            watcher = TreeWatcher(proc.pid)
            watcher.start()
            timed_out = False
            try:
                proc.wait(timeout=a.timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(proc.pid, 9)  # whole process group; payloads are session leaders
                proc.wait()
            end_ns = time.time_ns()
            time.sleep(1.0)
            watcher.stop()
            executions.append({
                "execution_id": exec_id, "scenario": name, "family": family, "kind": kind,
                "seed": seed, "host": manifest["host"], "root_pid": proc.pid,
                "pids": sorted(watcher.pids), "start_ns": start_ns, "end_ns": end_ns,
                "first_malicious_ns": first_malicious_ns(actions),
                "exit_code": proc.returncode, "timed_out": timed_out})
            shutil.rmtree(wd, ignore_errors=True)
            time.sleep(a.gap)
    finally:
        time.sleep(2.0)
        cap.stop()
        shutil.rmtree(scratch, ignore_errors=True)
        manifest.update(finished_wall_ns=time.time_ns(), events_captured=cap.count,
                        stream_gaps=cap.gaps, kbd_stats_after=kbd_stats(a.socket),
                        sensor_summaries=sh(["journalctl", "-u", "kb-sensor", "--no-pager", "-o", "cat",
                                             "--since", f"@{manifest['started_wall_ns'] // 10**9}"]).count("SENSOR] last"))
        entries = audit_entries(a.socket)
        manifest["audit_export_ok"] = entries is not None
        import labeling
        captured = labeling.load_jsonl(events_path)
        with open(os.path.join(root, "labels.jsonl"), "w") as f:
            for i, ex in enumerate(executions):
                ex = labeling.expand_pids(ex, captured)   # short-lived children the poll missed
                executions[i] = ex
                ex["kbd_audit"] = audit_for_execution(entries, ex)
                f.write(json.dumps(ex) + "\n")
        with open(os.path.join(root, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=1)
    print(f"done: {root}  ({cap.count} events, {cap.gaps} stream gaps, {len(executions)} executions)")
    if cap.count == 0:
        print("ERROR: no events were captured; this corpus is unusable", file=sys.stderr)
        return 3
    if cap.gaps:
        print(f"WARNING: {cap.gaps} stream gap(s); windows overlapping them are marked telemetry_gap", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
