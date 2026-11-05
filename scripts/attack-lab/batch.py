#!/usr/bin/env python3
"""
One unattended, time-boxed capture window on an ISOLATED lab VM, with guaranteed restore.

    batch.py --ack-isolated --ack-observe-only --seeds 2,3 --scenarios v2 --repeats 5 --out DIR [--max-minutes 55]
    batch.py --dry-run ...            # print the plan, change nothing

What it does, in order:
  1. preconditions: not root, passwordless sudo, kb-checker hold intact (no /etc/kb/checker.enabled),
     no leftover drop-ins from an earlier window, kbd and kb-sensor active;
  2. backs up /etc/kb/policy.yaml, then for the window ONLY: a kbd drop-in KB_OBSERVE_ONLY=1, a kb-sensor
     drop-in KB_SENSOR_EXIT_STATE=all + KB_BYTES_SENT=1, and `known_destinations` set in policy.yaml;
     restarts kbd and kb-sensor;
  3. runs runner.py once per seed (never starting a seed that would not finish inside --max-minutes);
  4. ALWAYS (finally / SIGINT / SIGTERM): removes the drop-ins, restores policy.yaml byte for byte, restarts
     kbd and kb-sensor, and verifies: observe-only gone, sensor flags gone, byte hook unloaded, kbd and
     kb-sensor active, kb-checker still down. It prints RESTORE OK or a loud RESTORE FAILED.

It never touches kb-checker, the network, the binaries or enforcement settings other than the temporary
KB_OBSERVE_ONLY. Real exploits are out of scope (this runs runner.py's scripted scenarios only).
Run it ON the VM as the ordinary lab user.
"""
import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

POLICY = "/etc/kb/policy.yaml"
KBD_DROPIN_DIR = "/etc/systemd/system/kbd.service.d"
SENSOR_DROPIN_DIR = "/etc/systemd/system/kb-sensor.service.d"
KBD_DROPIN = KBD_DROPIN_DIR + "/observe-only.conf"
SENSOR_DROPIN = SENSOR_DROPIN_DIR + "/capture.conf"
CHECKER_FLAG = "/etc/kb/checker.enabled"


def with_known_destinations(policy_text, hosts):
    """policy.yaml text with a top-level `known_destinations:` list of `hosts`, replacing any existing
    key (and its indented/comment continuation lines) and leaving everything else byte for byte."""
    lines = policy_text.split("\n")
    out, skipping = [], False
    for line in lines:
        if re.match(r"^known_destinations\s*:", line):
            skipping = True
            continue
        if skipping and (line.startswith((" ", "\t")) or line.strip() == ""):
            # indented continuation (list items / comments) belongs to the key we are replacing
            if line.strip() == "":
                skipping = False
                out.append(line)
            continue
        skipping = False
        out.append(line)
    text = "\n".join(out)
    if not text.endswith("\n"):
        text += "\n"
    return text + "known_destinations: [" + ", ".join(hosts) + "]\n"


def estimate_seed_minutes(scenarios, repeats, gap_s=6.0, overhead=0.85):
    """Planned minutes for one seed: sum of the scenarios' nominal seconds plus the inter-execution gap,
    times a calibration factor: the three captures so far took about 72 to 75% of the runner's nominal
    estimate, so 0.85 stays conservative."""
    from payloads import SCENARIOS
    total = sum(SCENARIOS[n][3] + gap_s for n in scenarios) * repeats
    return total * overhead / 60.0


def seeds_that_fit(seeds, per_seed_min, max_minutes):
    """How many of the requested seeds can start and finish inside the time box (in order)."""
    fit, used = [], 0.0
    for s in seeds:
        if used + per_seed_min > max_minutes:
            break
        fit.append(s)
        used += per_seed_min
    return fit


def sh(cmd, check=True, input_text=None, timeout=120):
    r = subprocess.run(cmd, capture_output=True, text=True, input=input_text, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed ({r.returncode}): {r.stderr.strip()[:200]}")
    return r.stdout


def sudo_write(path, text):
    sh(["sudo", "-n", "tee", path], input_text=text)


def unit_env(unit):
    return sh(["systemctl", "show", unit, "-p", "Environment", "--value"], check=False).strip()


def is_active(unit):
    return sh(["systemctl", "is-active", unit], check=False).strip() == "active"


def hook_loaded():
    out = sh(["sudo", "-n", "bpftool", "prog", "list"], check=False)
    return "sock_sendmsg" in out


class Window:
    """Applies the temporary settings and ALWAYS undoes them."""

    def __init__(self, hosts):
        self.hosts = hosts
        self.orig_policy = None
        self.applied = False

    def apply(self):
        self.orig_policy = sh(["sudo", "-n", "cat", POLICY])
        backup = os.path.expanduser(f"~/kb-batch-backup-{time.strftime('%Y%m%dT%H%M%S')}")
        os.makedirs(backup, exist_ok=True)
        with open(os.path.join(backup, "policy.yaml"), "w") as f:
            f.write(self.orig_policy)
        print(f"[batch] policy backup: {backup}/policy.yaml", flush=True)
        self.applied = True      # from here on, restore even if a step below fails
        sh(["sudo", "-n", "mkdir", "-p", KBD_DROPIN_DIR, SENSOR_DROPIN_DIR])
        sudo_write(KBD_DROPIN, "[Service]\nEnvironment=KB_OBSERVE_ONLY=1\n")
        sudo_write(SENSOR_DROPIN, "[Service]\nEnvironment=KB_SENSOR_EXIT_STATE=all\nEnvironment=KB_BYTES_SENT=1\n")
        if self.hosts:
            sudo_write(POLICY, with_known_destinations(self.orig_policy, self.hosts))
        sh(["sudo", "-n", "systemctl", "daemon-reload"])
        sh(["sudo", "-n", "systemctl", "restart", "kbd"])
        time.sleep(4)
        sh(["sudo", "-n", "systemctl", "restart", "kb-sensor"])
        time.sleep(10)
        if "KB_OBSERVE_ONLY=1" not in unit_env("kbd").split():
            raise RuntimeError("kbd is not in observe-only after the restart")
        env = unit_env("kb-sensor")
        if "KB_SENSOR_EXIT_STATE=all" not in env or "KB_BYTES_SENT=1" not in env:
            raise RuntimeError("kb-sensor flags missing after the restart")

    def restore(self):
        if not self.applied:
            return True
        problems = []
        for step in (
            lambda: sh(["sudo", "-n", "rm", "-f", KBD_DROPIN, SENSOR_DROPIN], check=False),
            lambda: sh(["sudo", "-n", "rmdir", KBD_DROPIN_DIR, SENSOR_DROPIN_DIR], check=False),
            lambda: sudo_write(POLICY, self.orig_policy) if self.orig_policy is not None else None,
            lambda: sh(["sudo", "-n", "systemctl", "daemon-reload"], check=False),
            lambda: sh(["sudo", "-n", "systemctl", "restart", "kbd"], check=False),
            lambda: time.sleep(4),
            lambda: sh(["sudo", "-n", "systemctl", "restart", "kb-sensor"], check=False),
            lambda: time.sleep(8),
        ):
            try:
                step()
            except Exception as e:  # noqa: BLE001 - keep restoring whatever else we can
                problems.append(str(e))
        if "KB_OBSERVE_ONLY" in unit_env("kbd"):
            problems.append("kbd still has KB_OBSERVE_ONLY")
        env = unit_env("kb-sensor")
        if "KB_SENSOR_EXIT_STATE" in env or "KB_BYTES_SENT" in env:
            problems.append("kb-sensor still has capture flags")
        if os.path.exists(KBD_DROPIN) or os.path.exists(SENSOR_DROPIN):
            problems.append("a drop-in file is still present")
        if hook_loaded():
            problems.append("byte hook still loaded")
        for unit in ("kbd", "kb-sensor"):
            if not is_active(unit):
                problems.append(f"{unit} not active")
        if os.path.exists(CHECKER_FLAG) or is_active("kb-checker"):
            problems.append("kb-checker hold violated")
        if problems:
            print("[batch] RESTORE FAILED: " + "; ".join(problems), file=sys.stderr, flush=True)
            return False
        print("[batch] RESTORE OK: drop-ins removed, policy restored, kbd and kb-sensor active, hook unloaded, kb-checker down", flush=True)
        return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ack-isolated", action="store_true", help="this VM is an isolated lab VM (required)")
    ap.add_argument("--ack-observe-only", action="store_true",
                    help="the operator approved running kbd in observe-only for this window (required)")
    ap.add_argument("--seeds", default="2")
    ap.add_argument("--scenarios", default="v2")
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-minutes", type=float, default=55.0)
    ap.add_argument("--known-hosts", default="127.0.0.3,127.0.0.5",
                    help="written to policy.yaml known_destinations for the window ('' = leave policy alone)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    from payloads import GROUPS
    names = list(GROUPS[a.scenarios]) if a.scenarios in GROUPS else a.scenarios.split(",")
    seeds = [int(x) for x in a.seeds.split(",")]
    per_seed = estimate_seed_minutes(names, a.repeats)
    fit = seeds_that_fit(seeds, per_seed, a.max_minutes)
    hosts = [h for h in a.known_hosts.split(",") if h]
    print(f"[batch] {len(names)} scenarios x {a.repeats} repeats, ~{per_seed:.0f} min per seed; "
          f"seeds {seeds} -> will run {fit} inside {a.max_minutes:.0f} min; known_destinations {hosts or 'unchanged'}", flush=True)
    if a.dry_run:
        return 0
    if not (a.ack_isolated and a.ack_observe_only):
        print("refusing to run: pass --ack-isolated and --ack-observe-only (operator approval for this window)", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        print("refusing to run as root", file=sys.stderr)
        return 2
    if not fit:
        print("refusing to run: not even one seed fits inside --max-minutes", file=sys.stderr)
        return 2
    try:
        sh(["sudo", "-n", "true"])
    except Exception as e:  # noqa: BLE001
        print(f"refusing to run: passwordless sudo is required ({e})", file=sys.stderr)
        return 2
    if os.path.exists(CHECKER_FLAG) or is_active("kb-checker"):
        print("refusing to run: kb-checker is up or enabled (maintenance hold)", file=sys.stderr)
        return 2
    if os.path.exists(KBD_DROPIN) or os.path.exists(SENSOR_DROPIN):
        print("refusing to run: a drop-in from an earlier window is still present; resolve that first", file=sys.stderr)
        return 2
    if not (is_active("kbd") and is_active("kb-sensor")):
        print("refusing to run: kbd and kb-sensor must both be active", file=sys.stderr)
        return 2

    def on_signal(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")

    signal.signal(signal.SIGTERM, on_signal)
    win = Window(hosts)
    ok = True
    try:
        win.apply()
        os.makedirs(a.out, exist_ok=True)
        for seed in fit:
            cmd = [sys.executable, os.path.join(HERE, "runner.py"), "--ack-isolated", "--scenarios", a.scenarios,
                   "--repeats", str(a.repeats), "--seed", str(seed), "--out", a.out]
            print(f"[batch] seed {seed}: {' '.join(cmd)}", flush=True)
            r = subprocess.run(cmd)
            if r.returncode != 0:
                print(f"[batch] runner exited {r.returncode} for seed {seed}; stopping the batch", file=sys.stderr, flush=True)
                ok = False
                break
    except BaseException as e:  # noqa: BLE001 - includes KeyboardInterrupt/SIGTERM; always fall through to restore
        print(f"[batch] interrupted or failed: {e!r}", file=sys.stderr, flush=True)
        ok = False
    finally:
        restored = win.restore()
    return 0 if (ok and restored) else 1


if __name__ == "__main__":
    sys.exit(main())
