#!/usr/bin/env python3
"""
KB attack-lab runner for LID-DS 2021 scenarios (real exploits).

Runs LID-DS scenarios (https://github.com/LID-DS/LID-DS, GPL-3.0, kept in its
own checkout, never copied into this repo) while recording kbd's event feed,
and writes a corpus in the SAME format as runner.py, so analyze.py,
baselines.py and labeling.py work on it unchanged:

    <out>/<run_id>/
        events.jsonl     what kbd emitted (+ {"gap":...} markers), no labels
        labels.jsonl     one record per execution (one LID-DS run)
        manifest.json    host, kernel, package, LID-DS revision, seed, ...

Each scenario is run in two modes:
    normal   normal behaviour only            -> kind "benign"
    exploit  normal behaviour + the exploit   -> kind "attack"

LID-DS victims run in Docker, so their processes are not children of this
runner. An execution's pids are the processes inside its VICTIM container,
found by cgroup membership while the run is live, then extended with
labeling.expand_pids for short-lived children. Processes of the exploit and
normal-traffic containers are recorded separately (pids_by_role) and are NOT
part of "pids": an alert on the attacker's own tools is not a detection of the
victim being compromised.

first_malicious_ns is the start time of the exploit container, as reported by
Docker. The exploit's first packet comes after that, so time-to-detect
measured from it is slightly pessimistic (an upper bound).

Usage (as an ordinary user in the `kb` group with passwordless sudo for the
LID-DS commands; LID-DS itself needs root for Docker and Sysdig):

    lidds_runner.py --lidds ~/LID-DS --list
    lidds_runner.py --lidds ~/LID-DS --ack-isolated --scenarios all --repeats 10 --seed 1 --out corpus
    lidds_runner.py --lidds ~/LID-DS --ack-isolated --scenarios CVE-2014-0160 --repeats 1 --dry-run

The LID-DS scenario CLI is not uniform across scenarios and wiki versions.
The default command is
    sudo -n {python} main.py {normal} {seconds} {exploit}
with normal mode = "1 <--normal-seconds> 0" and exploit mode = "1 -1 1"
(-1 = stop when the exploit ends). Check each scenario's README and override
with --cmd-template if a scenario differs.

THIS RUNS REAL EXPLOITS against containers on this host. Only on an isolated
lab VM with no route to other networks (--ack-isolated is required and is your
statement that it is one).
"""
import argparse
import json
import os
import platform
import random
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import runner  # noqa: E402  (shared helpers: kbd checks, audit export, stats)

POLL_S = 0.2
DEFAULT_TEMPLATE = "sudo -n {python} main.py {normal} {seconds} {exploit}"
MODES = {"normal": "benign", "exploit": "attack"}

# Container roles, guessed from container name or image. LID-DS names its
# containers per scenario; override with --victim-match if a scenario differs.
ROLE_PATTERNS = (
    ("exploit", re.compile(r"exploit|attack", re.I)),
    ("normal", re.compile(r"normal|client|user", re.I)),
    ("victim", re.compile(r"victim|server|target", re.I)),
)


# ----------------------------------------------------------------------------- pure helpers (tested)

def list_scenarios(lidds_root):
    """LID-DS scenario folders that have a main.py, sorted."""
    sdir = os.path.join(lidds_root, "scenarios")
    if not os.path.isdir(sdir):
        return []
    return sorted(d for d in os.listdir(sdir)
                  if os.path.isfile(os.path.join(sdir, d, "main.py")))


def build_plan(scenarios, modes, repeats, seed):
    """(scenario, mode, repeat, seed) tuples, seeded-shuffled like runner.build_plan."""
    rng = random.Random(seed)
    plan = [(s, m, i, rng.randint(0, 2**31 - 1)) for s in scenarios for m in modes for i in range(repeats)]
    rng.shuffle(plan)
    return plan


def command_for(template, python, mode, normal_seconds):
    if mode == "normal":
        args = {"normal": 1, "seconds": normal_seconds, "exploit": 0}
    elif mode == "exploit":
        args = {"normal": 1, "seconds": -1, "exploit": 1}
    else:
        raise ValueError(f"unknown mode {mode!r}")
    return shlex.split(template.format(python=python, **args))


def classify_role(name, image, victim_match=None):
    """'victim' | 'exploit' | 'normal' | 'unknown' for a container."""
    text = f"{name} {image}"
    if victim_match and re.search(victim_match, text, re.I):
        return "victim"
    for role, pat in ROLE_PATTERNS:
        if pat.search(text):
            return role
    return "unknown"


def pids_in_container(container_id, proc_root="/proc"):
    """Host pids whose cgroup path contains the container's full id
    (cgroup v1 and v2, Docker's docker-<id>.scope and /docker/<id> layouts)."""
    found = set()
    for name in os.listdir(proc_root):
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(proc_root, name, "cgroup")) as f:
                if container_id in f.read():
                    found.add(int(name))
        except OSError:
            continue
    return found


def parse_docker_ps(text):
    """`docker ps --no-trunc --format '{{.ID}}\\t{{.Names}}\\t{{.Image}}'` -> list of dicts."""
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0]:
            out.append({"id": parts[0], "name": parts[1], "image": parts[2]})
    return out


def parse_started_at(s):
    """Docker's RFC 3339 StartedAt (nanosecond precision, Z) -> epoch ns; None if unparsable."""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$", s.strip())
    if not m:
        return None
    import calendar
    y, mo, d, h, mi, se, frac = m.groups()
    secs = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(se)))
    frac_ns = int((frac or "0")[:9].ljust(9, "0"))
    return secs * 10**9 + frac_ns


def label_record(run_id, scenario, mode, rep, seed, host, runner_pid, start_ns, end_ns,
                 containers, pids_by_role, exit_code, timed_out):
    """One labels.jsonl record, in runner.py's schema plus LID-DS fields."""
    exploit_starts = [c["started_ns"] for c in containers if c["role"] == "exploit" and c.get("started_ns")]
    victim = sorted(pids_by_role.get("victim", ()))
    # root_pid is the victim container's init process, NOT the runner's own
    # process: labeling.expand_pids adds every descendant of root_pid, and the
    # runner's descendants are LID-DS's framework (docker CLI, sysdig), not the victim.
    victim_inits = [c["host_pid"] for c in containers if c["role"] == "victim" and c.get("host_pid")]
    root_pid = victim_inits[0] if victim_inits else (victim[0] if victim else -1)
    return {
        "execution_id": f"{run_id}-lidds-{scenario}-{mode}-{rep:03d}",
        "scenario": f"lidds_{scenario}_{mode}",
        "family": f"lidds_{scenario}",
        "kind": MODES[mode],
        "source": "lidds",
        "lidds_scenario": scenario,
        "mode": mode,
        "seed": seed,
        "host": host,
        "root_pid": root_pid,
        "runner_pid": runner_pid,
        "pids": victim,
        "pids_by_role": {r: sorted(p) for r, p in pids_by_role.items()},
        "victim_found": bool(victim),
        "containers": containers,
        "start_ns": start_ns,
        "end_ns": end_ns,
        "first_malicious_ns": (min(exploit_starts) if exploit_starts else None) if mode == "exploit" else None,
        "first_malicious_source": "exploit_container_start" if mode == "exploit" else None,
        "exit_code": exit_code,
        "timed_out": timed_out,
    }


# ----------------------------------------------------------------------------- live watchers

def docker(args, timeout=10):
    try:
        r = subprocess.run(["sudo", "-n", "docker", *args], capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except Exception:  # noqa: BLE001
        return ""


class ContainerWatcher(threading.Thread):
    """Records every container that appears during one execution (ignoring those
    running before it started) and the host pids inside each, by role."""

    def __init__(self, preexisting, victim_match=None):
        super().__init__(daemon=True)
        self.pre = set(preexisting)
        self.victim_match = victim_match
        self.containers = {}          # id -> record
        self.pids_by_role = {}        # role -> set of host pids
        self._halt = threading.Event()

    def _refresh(self):
        for c in parse_docker_ps(docker(["ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}"])):
            if c["id"] in self.pre:
                continue
            if c["id"] not in self.containers:
                info = docker(["inspect", "-f", "{{.State.Pid}}\t{{.State.StartedAt}}", c["id"]]).strip().split("\t")
                c["role"] = classify_role(c["name"], c["image"], self.victim_match)
                c["host_pid"] = int(info[0]) if info and info[0].isdigit() else None
                c["started_ns"] = parse_started_at(info[1]) if len(info) > 1 else None
                self.containers[c["id"]] = c
        for cid, c in self.containers.items():
            pids = pids_in_container(cid)
            if c.get("host_pid"):
                pids.add(c["host_pid"])
            self.pids_by_role.setdefault(c["role"], set()).update(pids)

    def run(self):
        while not self._halt.is_set():
            self._refresh()
            time.sleep(POLL_S)

    def stop(self):
        self._halt.set()
        self.join(timeout=5)
        self._refresh()


def stop_new_containers(watcher):
    """Stop only containers this execution started (never anything pre-existing)."""
    for cid in watcher.containers:
        docker(["stop", "-t", "5", cid], timeout=30)


# ----------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lidds", required=True, help="path to the LID-DS checkout")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--ack-isolated", action="store_true",
                    help="I confirm this is an isolated lab VM with no route to other networks")
    ap.add_argument("--scenarios", default="all")
    ap.add_argument("--modes", default="normal,exploit")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--normal-seconds", type=int, default=60)
    ap.add_argument("--python", default="python3.7", help="interpreter LID-DS was installed into")
    ap.add_argument("--cmd-template", default=DEFAULT_TEMPLATE)
    ap.add_argument("--victim-match", default=None, help="regex on container name/image marking the victim")
    ap.add_argument("--gap", type=float, default=10.0, help="seconds between executions")
    ap.add_argument("--timeout", type=float, default=900.0, help="per-execution hard limit")
    ap.add_argument("--out", default="corpus")
    ap.add_argument("--socket", default="/run/kb/kba.sock")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--allow-containment", action="store_true",
                    help="record even though kbd applies automatic containment (labelled in the manifest)")
    a = ap.parse_args()

    available = list_scenarios(a.lidds)
    if a.list:
        for s in available:
            print(s)
        return 0
    if not available:
        print(f"no LID-DS scenarios found under {a.lidds}/scenarios", file=sys.stderr)
        return 2
    names = available if a.scenarios == "all" else a.scenarios.split(",")
    unknown = [n for n in names if n not in available]
    modes = a.modes.split(",")
    bad_modes = [m for m in modes if m not in MODES]
    if unknown or bad_modes:
        print(f"unknown scenarios {unknown} or modes {bad_modes}", file=sys.stderr)
        return 2
    plan = build_plan(names, modes, a.repeats, a.seed)
    print(f"{len(plan)} executions")
    if a.dry_run:
        for s, m, i, sd in plan:
            print(f"  {s} {m} #{i} seed={sd}: {' '.join(command_for(a.cmd_template, a.python, m, a.normal_seconds))}")
        return 0

    if not a.ack_isolated:
        print("refusing to run: pass --ack-isolated to confirm this is an isolated lab VM", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        print("refusing to run as root: run as an ordinary user in the kb group with passwordless sudo "
              "for docker and the LID-DS interpreter", file=sys.stderr)
        return 2
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        print("refusing to run: `sudo -n` needs a password; LID-DS needs root for Docker and Sysdig", file=sys.stderr)
        return 2
    observe_only = runner.kbd_observe_only()
    if observe_only is not True and not a.allow_containment:
        print("refusing to run: kbd is not in observe-only mode (KB_OBSERVE_ONLY=1); see runner.py's "
              "message for how to set it, or pass --allow-containment", file=sys.stderr)
        return 2

    from capture import Capture
    run_id = time.strftime("%Y%m%dT%H%M%S")
    root = os.path.join(a.out, run_id)
    os.makedirs(root)
    events_path = os.path.join(root, "events.jsonl")
    cap = Capture(events_path, a.socket)
    try:
        cap.start()
    except RuntimeError as e:
        print(f"refusing to run: {e}", file=sys.stderr)
        shutil.rmtree(root, ignore_errors=True)
        return 2

    manifest = {
        "run_id": run_id, "source": "lidds", "host": platform.node(), "kernel": platform.release(),
        "package": runner.sh(["dpkg-query", "-W", "-f=${Version}", "kernel-borderlands"])
                   or runner.sh(["pacman", "-Q", "kernel-borderlands"]),
        "feature_schema": runner.SCHEMA_VERSION, "seed": a.seed, "repeats": a.repeats,
        "scenarios": names, "modes": modes, "normal_seconds": a.normal_seconds,
        "cmd_template": a.cmd_template, "python": a.python,
        "lidds_path": os.path.abspath(a.lidds),
        "lidds_revision": runner.sh(["git", "-C", a.lidds, "rev-parse", "HEAD"]),
        "docker_version": docker(["version", "--format", "{{.Server.Version}}"]).strip(),
        "kbd_stats_before": runner.kbd_stats(a.socket),
        "containment_active": observe_only is not True,
        "started_wall_ns": time.time_ns(),
    }
    executions = []
    try:
        for n, (scenario, mode, rep, seed) in enumerate(plan):
            cmd = command_for(a.cmd_template, a.python, mode, a.normal_seconds)
            print(f"[{n + 1}/{len(plan)}] {scenario} {mode} #{rep}", flush=True)
            pre = {c["id"] for c in parse_docker_ps(docker(["ps", "--no-trunc", "--format",
                                                             "{{.ID}}\t{{.Names}}\t{{.Image}}"]))}
            watcher = ContainerWatcher(pre, a.victim_match)
            watcher.start()
            start_ns = time.time_ns()
            proc = subprocess.Popen(cmd, cwd=os.path.join(a.lidds, "scenarios", scenario),
                                    start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            timed_out = False
            try:
                proc.wait(timeout=a.timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                subprocess.run(["sudo", "-n", "kill", "-9", f"-{proc.pid}"], capture_output=True)
                proc.wait()
            end_ns = time.time_ns()
            time.sleep(1.0)
            watcher.stop()
            stop_new_containers(watcher)
            rec = label_record(run_id, scenario, mode, rep, seed, manifest["host"], proc.pid, start_ns, end_ns,
                               sorted(watcher.containers.values(), key=lambda c: c.get("started_ns") or 0),
                               watcher.pids_by_role, proc.returncode, timed_out)
            if not rec["victim_found"]:
                print(f"  WARNING: no victim container identified for {scenario}; "
                      f"containers seen: {[c['name'] for c in rec['containers']]} (use --victim-match)",
                      file=sys.stderr)
            executions.append(rec)
            time.sleep(a.gap)
    finally:
        time.sleep(2.0)
        cap.stop()
        manifest.update(finished_wall_ns=time.time_ns(), events_captured=cap.count,
                        stream_gaps=cap.gaps, kbd_stats_after=runner.kbd_stats(a.socket))
        entries = runner.audit_entries(a.socket)
        manifest["audit_export_ok"] = entries is not None
        import labeling
        captured = labeling.load_jsonl(events_path)
        with open(os.path.join(root, "labels.jsonl"), "w") as f:
            for i, ex in enumerate(executions):
                ex = labeling.expand_pids(ex, captured)
                ex["pids"] = [p for p in ex["pids"] if p > 0]
                executions[i] = ex
                ex["kbd_audit"] = runner.audit_for_execution(entries, ex)
                f.write(json.dumps(ex) + "\n")
        with open(os.path.join(root, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=1)
    missing = sum(1 for e in executions if not e["victim_found"])
    print(f"done: {root}  ({cap.count} events, {cap.gaps} stream gaps, {len(executions)} executions, "
          f"{missing} without an identified victim)")
    if cap.count == 0:
        print("ERROR: no events were captured; this corpus is unusable", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
