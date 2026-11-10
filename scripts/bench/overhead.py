#!/usr/bin/env python3
"""
Sensor-overhead measurement (plan item C3): alternating runs of microbench.c with the Kernel
Borderlands services off and on, three modes:

    off    kbd and kb-sensor stopped
    on     both running with the shipped defaults (every sensor program loaded; the optional
           bytes-sent hook is NOT loaded)
    bytes  as "on" plus KB_BYTES_SENT=1 on kb-sensor (the security_socket_sendmsg kprobe)

    overhead.py --ack-isolated --commit <git sha> --out result.json [--rounds 5] [--batches 7] [--cpu 2]

Run on the lab VM as an ordinary user with passwordless sudo, after compiling microbench.c next to
this file (gcc -O2 -o microbench microbench.c). It STOPS the protection for the duration of each "off"
segment, so it requires --ack-isolated. The order of the modes is rotated every round so a slow
drift (thermal, cache) does not favour one mode. kb-checker is never started. On exit, normal or
not, the bench drop-in is removed and kbd and kb-sensor are started again; the restore is verified.

Reports the median over rounds per operation per mode, with the min..max across rounds, and the
change versus "off". Numbers from a VM are NOT comparable with the host numbers on the project site.
"""
import argparse
import json
import os
import signal
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DROPIN_DIR = "/etc/systemd/system/kb-sensor.service.d"
DROPIN = os.path.join(DROPIN_DIR, "bench.conf")
MODES = ("off", "on", "bytes")


def sh(cmd, check=True, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check, capture_output=True, text=True, **kw)


def sudo(cmd, check=True):
    return sh(["sudo", "-n"] + cmd, check=check)


def active(unit):
    return sh(["systemctl", "is-active", unit], check=False).stdout.strip() == "active"


def sensor_env_has_bytes():
    pid = sh(["systemctl", "show", "-p", "MainPID", "--value", "kb-sensor"]).stdout.strip()
    if not pid or pid == "0":
        return False
    env = sudo(["cat", f"/proc/{pid}/environ"], check=False).stdout
    return "KB_BYTES_SENT=1" in env.split("\0")


def clear_start_limit():
    """kb-sensor.service allows 5 starts per 2 minutes (systemd default); every segment restarts it."""
    sudo(["systemctl", "reset-failed", "kbd", "kb-sensor"], check=False)


def set_mode(mode, settle):
    if mode == "off":
        sudo(["systemctl", "stop", "kb-sensor"], check=False)
        sudo(["systemctl", "stop", "kbd"], check=False)
        assert not active("kb-sensor") and not active("kbd"), "services did not stop"
    else:
        if mode == "bytes":
            sudo(["mkdir", "-p", DROPIN_DIR])
            sh(["sudo", "-n", "tee", DROPIN], input="[Service]\nEnvironment=KB_BYTES_SENT=1\n")
        else:
            sudo(["rm", "-f", DROPIN])
        sudo(["systemctl", "daemon-reload"])
        clear_start_limit()
        sudo(["systemctl", "restart", "kbd"])
        time.sleep(3)
        clear_start_limit()
        sudo(["systemctl", "restart", "kb-sensor"])
        time.sleep(settle)
        assert active("kbd") and active("kb-sensor"), "services did not start"
        assert sensor_env_has_bytes() == (mode == "bytes"), "KB_BYTES_SENT state does not match mode"
    assert not active("kb-checker"), "kb-checker is running"


def restore():
    sudo(["rm", "-f", DROPIN], check=False)
    try:
        sudo(["rmdir", DROPIN_DIR], check=False)
    except Exception:
        pass
    sudo(["systemctl", "daemon-reload"], check=False)
    clear_start_limit()
    sudo(["systemctl", "restart", "kbd"], check=False)
    time.sleep(3)
    clear_start_limit()
    sudo(["systemctl", "restart", "kb-sensor"], check=False)
    time.sleep(5)
    ok = (active("kbd") and active("kb-sensor") and not active("kb-checker")
          and not os.path.exists(DROPIN) and not sensor_env_has_bytes())
    print("[bench] RESTORE", "OK: drop-in removed, kbd and kb-sensor active, bytes hook off, kb-checker down"
          if ok else "FAILED: check the services by hand", flush=True)
    return ok


def run_bench(cpu, batches):
    exe = os.path.join(HERE, "microbench")
    out = sh(["taskset", "-c", str(cpu), exe, str(batches)]).stdout.strip()
    return json.loads(out)


def summarise(results):
    ops = list(next(iter(results["off"])).keys())
    table = {}
    for op in ops:
        row = {}
        for m in MODES:
            vals = [r[op] for r in results[m]]
            row[m] = {"median": statistics.median(vals), "min": min(vals), "max": max(vals), "n": len(vals)}
        base = row["off"]["median"]
        for m in ("on", "bytes"):
            row[m]["delta"] = row[m]["median"] - base
            row[m]["pct"] = 100.0 * (row[m]["median"] - base) / base if base else None
        table[op] = row
    return table


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ack-isolated", action="store_true", help="this VM is an isolated lab VM (required)")
    ap.add_argument("--commit", required=True, help="git commit of the build under test, recorded in the result")
    ap.add_argument("--out", required=True)
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--batches", type=int, default=7)
    ap.add_argument("--cpu", type=int, default=2)
    ap.add_argument("--settle", type=int, default=8, help="seconds to let the sensor settle after a start")
    a = ap.parse_args()
    if not a.ack_isolated:
        sys.exit("refusing: this stops the protection for a while; pass --ack-isolated on the lab VM only")
    if os.geteuid() == 0:
        sys.exit("run as an ordinary user (sudo -n is used for the service changes)")
    if not os.path.exists(os.path.join(HERE, "microbench")):
        sys.exit("compile first: gcc -O2 -o microbench microbench.c")
    if sudo(["true"], check=False).returncode != 0:
        sys.exit("passwordless sudo is required")
    if not (active("kbd") and active("kb-sensor")) or active("kb-checker"):
        sys.exit("expected kbd and kb-sensor active and kb-checker inactive at the start")

    meta = {"commit": a.commit, "rounds": a.rounds, "batches": a.batches, "cpu": a.cpu,
            "kernel": os.uname().release, "nproc": os.cpu_count(),
            "kbd_sha256": sudo(["sha256sum", "/usr/bin/kbd"]).stdout.split()[0],
            "sensor_sha256": sudo(["sha256sum", "/usr/bin/kbd_sensor"]).stdout.split()[0],
            "start": time.strftime("%Y-%m-%dT%H:%M:%S")}
    for line in open("/proc/cpuinfo"):
        if line.startswith("model name"):
            meta["cpu_model"] = line.split(":", 1)[1].strip()
            break

    def on_term(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, on_term)

    results = {m: [] for m in MODES}
    order_log = []
    ok = False
    try:
        for r in range(a.rounds):
            order = list(MODES[r % 3:]) + list(MODES[:r % 3])   # rotate each round
            order_log.append(order)
            for m in order:
                set_mode(m, a.settle)
                res = run_bench(a.cpu, a.batches)
                results[m].append(res)
                print(f"[bench] round {r + 1}/{a.rounds} {m:5} " + " ".join(f"{k}={v}" for k, v in res.items()), flush=True)
    finally:
        ok = restore()
    meta["restore_ok"] = ok
    meta["order"] = order_log
    meta["end"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    complete = all(len(v) == a.rounds for v in results.values())
    table = summarise(results) if complete else None
    with open(a.out, "w") as fh:
        json.dump({"meta": meta, "runs": results, "summary": table}, fh, indent=1)
    if table:
        print(f"\n{'operation':20} {'off':>12} {'on':>12} {'on %':>8} {'bytes':>12} {'bytes %':>8}")
        for op, row in table.items():
            print(f"{op:20} {row['off']['median']:12.1f} {row['on']['median']:12.1f} {row['on']['pct']:+7.1f}% "
                  f"{row['bytes']['median']:12.1f} {row['bytes']['pct']:+7.1f}%")
    sys.exit(0 if ok and complete else 1)


if __name__ == "__main__":
    main()
